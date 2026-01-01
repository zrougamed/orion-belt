package recording

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zrougamed/orion-belt/pkg/common"
)

// Recorder handles SSH session recording
type Recorder struct {
	storagePath string
	logger      *common.Logger
	mu          sync.RWMutex
	sessions    map[string]*SessionRecorder
}

// SessionRecorder records a single SSH session
type SessionRecorder struct {
	sessionID string
	file      *os.File
	writer    io.Writer
	startTime time.Time
	mu        sync.Mutex
}

// RecordEntry represents a recorded entry in the session
type RecordEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Data      []byte    `json:"data"`
	Direction string    `json:"direction"` // input or output
}

// NewRecorder creates a new session recorder
func NewRecorder(storagePath string, logger *common.Logger) (*Recorder, error) {
	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(storagePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	return &Recorder{
		storagePath: storagePath,
		logger:      logger,
		sessions:    make(map[string]*SessionRecorder),
	}, nil
}

// StartRecording starts recording a new session
func (r *Recorder) StartRecording(sessionID string) (*SessionRecorder, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if already recording
	if _, exists := r.sessions[sessionID]; exists {
		return nil, fmt.Errorf("session already being recorded: %s", sessionID)
	}

	// Create session file
	filename := filepath.Join(r.storagePath, fmt.Sprintf("%s.log", sessionID))
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create recording file: %w", err)
	}

	recorder := &SessionRecorder{
		sessionID: sessionID,
		file:      file,
		writer:    file,
		startTime: time.Now(),
	}

	// Write header
	header := fmt.Sprintf("# Orion-Belt Session Recording\n# Session ID: %s\n# Start Time: %s\n\n",
		sessionID, recorder.startTime.Format(time.RFC3339))
	file.WriteString(header)

	r.sessions[sessionID] = recorder
	r.logger.Info("Started recording session: %s", sessionID)

	return recorder, nil
}

// StopRecording stops recording a session
func (r *Recorder) StopRecording(sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	recorder, exists := r.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not being recorded: %s", sessionID)
	}

	// Write footer
	footer := fmt.Sprintf("\n# End Time: %s\n# Duration: %s\n",
		time.Now().Format(time.RFC3339),
		time.Since(recorder.startTime))
	recorder.file.WriteString(footer)

	// Close file
	if err := recorder.file.Close(); err != nil {
		r.logger.Error("Failed to close recording file for session %s: %v", sessionID, err)
	}

	delete(r.sessions, sessionID)
	r.logger.Info("Stopped recording session: %s", sessionID)

	return nil
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

// GetRecordingPath returns the path to a session recording
func (r *Recorder) GetRecordingPath(sessionID string) string {
	return filepath.Join(r.storagePath, fmt.Sprintf("%s.log", sessionID))
}

// Write writes data to the session recording
func (s *SessionRecorder) Write(data []byte, direction string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	timestamp := time.Now().Format(time.RFC3339Nano)
	entry := fmt.Sprintf("[%s] [%s] %s\n", timestamp, direction, string(data))

	_, err := s.file.WriteString(entry)
	if err != nil {
		return fmt.Errorf("failed to write to recording: %w", err)
	}

	return nil
}

// WriteInput writes input data (from client)
func (s *SessionRecorder) WriteInput(data []byte) error {
	return s.Write(data, "input")
}

// WriteOutput writes output data (from server)
func (s *SessionRecorder) WriteOutput(data []byte) error {
	return s.Write(data, "output")
}

// Flush flushes the recording to disk
func (s *SessionRecorder) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.file.Sync()
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
	// Record the data
	if err := rw.recorder.WriteOutput(p); err != nil {
		// Log error but don't fail the write
		fmt.Fprintf(os.Stderr, "Recording error: %v\n", err)
	}

	// Write to actual writer
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
	// Read from actual reader
	n, err = rr.reader.Read(p)

	// Record the data
	if n > 0 {
		if err := rr.recorder.WriteInput(p[:n]); err != nil {
			// Log error but don't fail the read
			fmt.Fprintf(os.Stderr, "Recording error: %v\n", err)
		}
	}

	return n, err
}
