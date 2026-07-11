package recording

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/zrougamed/orion-belt/pkg/common"
)

// ANSI regex to strip terminal colors and cursor movements
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

type Recorder struct {
	storagePath string
	logger      *common.Logger
	crypto      *Crypto
	mu          sync.RWMutex
	sessions    map[string]*SessionRecorder
}

// SessionRecorder records a single SSH session
type SessionRecorder struct {
	sessionID string
	buf       *bytes.Buffer
	filePath  string
	crypto    *Crypto
	startTime time.Time
	mu        sync.Mutex
}

// NewRecorder creates a new session recorder
func NewRecorder(storagePath string, logger *common.Logger) (*Recorder, error) {
	if err := os.MkdirAll(storagePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	return &Recorder{
		storagePath: storagePath,
		logger:      logger,
		sessions:    make(map[string]*SessionRecorder),
	}, nil
}

// SetCrypto enables at-rest encryption for recordings.
func (r *Recorder) SetCrypto(c *Crypto) {
	r.crypto = c
}

// StartRecording starts recording a new session
func (r *Recorder) StartRecording(sessionID string) (*SessionRecorder, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sessions[sessionID]; exists {
		return nil, fmt.Errorf("session already being recorded: %s", sessionID)
	}

	filename := r.GetRecordingPath(sessionID)
	recorder := &SessionRecorder{
		sessionID: sessionID,
		buf:       &bytes.Buffer{},
		filePath:  filename,
		crypto:    r.crypto,
		startTime: time.Now(),
	}

	header := fmt.Sprintf("# Orion-Belt Session Recording\n# Session ID: %s\n# Start Time: %s\n\n",
		sessionID, recorder.startTime.Format(time.RFC3339))
	recorder.buf.WriteString(header)

	r.sessions[sessionID] = recorder
	r.logger.Info("Started recording session: %s", sessionID)

	return recorder, nil
}

// StopRecording stops recording a session and flushes (optionally encrypted) to disk
func (r *Recorder) StopRecording(sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	recorder, exists := r.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not being recorded: %s", sessionID)
	}

	footer := fmt.Sprintf("\n# End Time: %s\n# Duration: %s\n",
		time.Now().Format(time.RFC3339),
		time.Since(recorder.startTime))
	recorder.mu.Lock()
	recorder.buf.WriteString(footer)
	plain := append([]byte(nil), recorder.buf.Bytes()...)
	recorder.mu.Unlock()

	var err error
	if recorder.crypto != nil && recorder.crypto.Enabled() {
		err = recorder.crypto.EncryptAndWrite(recorder.filePath, plain)
	} else {
		err = os.WriteFile(recorder.filePath, plain, 0600)
	}
	if err != nil {
		r.logger.Error("Failed to write recording for session %s: %v", sessionID, err)
	}

	delete(r.sessions, sessionID)
	r.logger.Info("Stopped recording session: %s", sessionID)

	return err
}

// GetRecorder returns a session recorder
func (r *Recorder) GetRecorder(sessionID string) (*SessionRecorder, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	recorder, exists := r.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not being recorded: %s", sessionID)
	}

	return recorder, nil
}

// GetRecordingStoragePath returns the path to the recorder storage path
func (r *Recorder) GetRecordingStoragePath() string {
	return r.storagePath
}

// GetRecordingPath returns the path to a session recording
func (r *Recorder) GetRecordingPath(sessionID string) string {
	return filepath.Join(r.storagePath, fmt.Sprintf("%s.txt", sessionID))
}

// Write writes data to the session recording buffer
func (s *SessionRecorder) Write(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanData := ansiRegex.ReplaceAll(data, []byte(""))
	_, err := s.buf.Write(cleanData)
	if err != nil {
		return fmt.Errorf("failed to write to recording: %w", err)
	}
	return nil
}

// RecordingWriter wraps an io.Writer to record data
type RecordingWriter struct {
	writer   io.Writer
	recorder *SessionRecorder
}

// NewRecordingWriter creates a new recording writer
func NewRecordingWriter(writer io.Writer, recorder *SessionRecorder) *RecordingWriter {
	return &RecordingWriter{
		writer:   writer,
		recorder: recorder,
	}
}

// Write writes data and records it
func (rw *RecordingWriter) Write(p []byte) (n int, err error) {
	if err := rw.recorder.Write(p); err != nil {
		fmt.Fprintf(os.Stderr, "Recording error: %v\n", err)
	}
	return rw.writer.Write(p)
}

// RecordingReader wraps an io.Reader to record data
type RecordingReader struct {
	reader   io.Reader
	recorder *SessionRecorder
}

// NewRecordingReader creates a new recording reader
func NewRecordingReader(reader io.Reader, recorder *SessionRecorder) *RecordingReader {
	return &RecordingReader{
		reader:   reader,
		recorder: recorder,
	}
}

// Read reads data and records it
func (rr *RecordingReader) Read(p []byte) (n int, err error) {
	n, err = rr.reader.Read(p)
	if n > 0 && rr.recorder != nil {
		if werr := rr.recorder.Write(p[:n]); werr != nil {
			fmt.Fprintf(os.Stderr, "Recording error: %v\n", werr)
		}
	}
	return n, err
}
