package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"mitmania/internal/telemetry"
)

// S3Storage is the S3 Storage backend. Keys are used verbatim as S3
// object names — S3 has no flat-directory scaling problem the way
// PosixStorage's sharding avoids, so no key transformation is needed
// here; a caller's already-sharded key (built for PosixStorage's benefit)
// just becomes a "/"-containing object name, which S3 treats as an
// ordinary flat key.
//
// S3Storage does not implement Linker: there's no cheap alias primitive
// to back the leaf cache's names/ operator index with, and that index is
// never on the serving path — so it's simply absent on this backend
// rather than emulated.
type S3Storage struct {
	client *minio.Client
	bucket string
}

// newS3Storage constructs an S3Storage from a parsed
// "s3://KEY:SECRET@host/?bucket=...&region=..." URL. An optional
// "?secure=false" opts out of TLS, for local S3-compatible endpoints
// (e.g. MinIO in dev) that don't terminate it themselves; defaults true.
func newS3Storage(u *url.URL) (*S3Storage, error) {
	bucket := u.Query().Get("bucket")
	if bucket == "" {
		return nil, fmt.Errorf("storage: s3: missing ?bucket=")
	}
	region := u.Query().Get("region")
	if region == "" {
		region = "us-east-1"
	}

	accessKey := u.User.Username()
	secretKey, hasSecret := u.User.Password()
	if accessKey == "" || !hasSecret {
		return nil, fmt.Errorf("storage: s3: missing credentials (need s3://KEY:SECRET@host/...)")
	}

	secure := true
	if v := u.Query().Get("secure"); v != "" {
		var err error
		secure, err = strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("storage: s3: invalid ?secure=%q: %w", v, err)
		}
	}

	if u.Host == "" {
		return nil, fmt.Errorf("storage: s3: missing host")
	}

	baseTransport, err := minio.DefaultTransport(secure)
	if err != nil {
		return nil, fmt.Errorf("storage: s3: transport: %w", err)
	}

	client, err := minio.New(u.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: secure,
		Region: region,
		// s3:// is our own dependency, not client traffic passing
		// through us — always carries traceparent, regardless of
		// --otel-propagate-upstream, same as outcall brokers.
		Transport: &tracePropagatingTransport{next: baseTransport},
	})
	if err != nil {
		return nil, fmt.Errorf("storage: s3: %w", err)
	}
	return &S3Storage{client: client, bucket: bucket}, nil
}

// tracePropagatingTransport injects the current span's W3C traceparent
// (from the request's own context, which minio-go always sets via
// http.NewRequestWithContext) into every outgoing S3 request.
type tracePropagatingTransport struct {
	next http.RoundTripper
}

func (t *tracePropagatingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	telemetry.InjectAlways(req.Context(), req.Header)
	return t.next.RoundTrip(req)
}

func (s *S3Storage) Get(ctx context.Context, key string) ([]byte, Version, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return nil, "", ErrNotExist
		}
		return nil, "", fmt.Errorf("storage: s3: get %s: %w", key, err)
	}
	defer obj.Close()

	info, err := obj.Stat()
	if err != nil {
		if isNotFound(err) {
			return nil, "", ErrNotExist
		}
		return nil, "", fmt.Errorf("storage: s3: stat %s: %w", key, err)
	}

	data, err := io.ReadAll(obj)
	if err != nil {
		return nil, "", fmt.Errorf("storage: s3: read %s: %w", key, err)
	}
	return data, Version(info.ETag), nil
}

func (s *S3Storage) Put(ctx context.Context, key string, data []byte) error {
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{})
	if err != nil {
		return fmt.Errorf("storage: s3: put %s: %w", key, err)
	}
	return nil
}

func (s *S3Storage) Delete(ctx context.Context, key string) error {
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("storage: s3: delete %s: %w", key, err)
	}
	return nil
}

func (s *S3Storage) DeletePrefix(ctx context.Context, prefix string) error {
	objectsCh := make(chan minio.ObjectInfo)
	go func() {
		defer close(objectsCh)
		for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
			if obj.Err != nil {
				continue // surfaced again below via RemoveObjects failing on a short read, good enough for a best-effort wipe
			}
			objectsCh <- obj
		}
	}()
	for rmErr := range s.client.RemoveObjects(ctx, s.bucket, objectsCh, minio.RemoveObjectsOptions{}) {
		if rmErr.Err != nil {
			return fmt.Errorf("storage: s3: delete prefix %s: %w", prefix, rmErr.Err)
		}
	}
	return nil
}

func (s *S3Storage) Stat(ctx context.Context, key string) (Version, error) {
	info, err := s.client.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		if isNotFound(err) {
			return "", ErrNotExist
		}
		return "", fmt.Errorf("storage: s3: stat %s: %w", key, err)
	}
	return Version(info.ETag), nil
}

func (s *S3Storage) List(ctx context.Context, prefix string) ([]Entry, error) {
	var entries []Entry
	for obj := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if obj.Err != nil {
			return nil, fmt.Errorf("storage: s3: list %s: %w", prefix, obj.Err)
		}
		entries = append(entries, Entry{Key: obj.Key, Version: Version(obj.ETag)})
	}
	return entries, nil
}

func isNotFound(err error) bool {
	resp := minio.ToErrorResponse(err)
	return resp.Code == minio.NoSuchKey || resp.StatusCode == 404
}
