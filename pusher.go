package tacsv2

import (
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/ohsoo/tacsv2/model/ecstcsnewservice"
	"go.uber.org/zap"
)

const (
	// http://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html
	// Truncation logic will assume this constant value is larger than perEventHeaderBytes + len(truncatedSuffix)
	defaultMaxEventPayloadBytes = 1024 * 256 // 256KB
	// http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogEvents.html
	maxRequestEventCount   = 10000
	perEventHeaderBytes    = 26
	maxRequestPayloadBytes = 1024 * 1024 * 1

	truncatedSuffix = "[Truncated...]"

	eventTimestampLimitInPast  = 14 * 24 * time.Hour // None of the log events in the batch can be older than 14 days
	evenTimestampLimitInFuture = -2 * time.Hour      // None of the log events in the batch can be more than 2 hours in the future.
)

var (
	maxEventPayloadBytes = defaultMaxEventPayloadBytes
)

// Event struct to present a log event.
type Event struct {
	InputLogEvent *ecstcsnewservice.LogEvent
	// The time which log generated.
	GeneratedTime time.Time
	// Identify the event's log group and stream name.
	StreamKey
}

// StreamKey identifies the log's destination.
type StreamKey struct {
	LogGroupName  string
	LogStreamName string
}

// NewEvent creates a new log event.
// logType will be propagated to LogEventBatch and used by logPusher to determine which client to call PutSystemLogEvents.
func NewEvent(timestampMs int64, message string) *Event {
	event := &Event{
		InputLogEvent: &ecstcsnewservice.LogEvent{
			Timestamp: aws.Time(time.UnixMilli(timestampMs).UTC()),
			Message:   aws.String(message)},
	}
	return event
}

func (logEvent *Event) Validate(logger *zap.Logger) error {
	if logEvent.eventPayloadBytes() > maxEventPayloadBytes {
		logger.Warn("logpusher: the single log event size is larger than the max event payload allowed. Truncating the log event.",
			zap.Int("SingleLogEventSize", logEvent.eventPayloadBytes()), zap.Int("maxEventPayloadBytes", maxEventPayloadBytes))

		newPayload := (*logEvent.InputLogEvent.Message)[0:(maxEventPayloadBytes - perEventHeaderBytes - len(truncatedSuffix))]
		newPayload += truncatedSuffix
		logEvent.InputLogEvent.Message = &newPayload
	}

	if logEvent.InputLogEvent.Timestamp.IsZero() {
		// Use the current time if the log is missing a timestamp.
		logEvent.InputLogEvent.Timestamp = aws.Time(time.Now().UTC())
	}
	if len(*logEvent.InputLogEvent.Message) == 0 {
		return errors.New("empty log event message")
	}

	// http://docs.aws.amazon.com/goto/SdkForGoV1/logs-2014-03-28/PutLogEvents
	// * None of the log events in the batch can be more than 2 hours in the
	// future.
	// * None of the log events in the batch can be older than 14 days or the
	// retention period of the log group.
	currentTime := time.Now().UTC()
	logTimestampLimitInPast := currentTime.Add(-14 * 24 * time.Hour)
	logTimestampLimitInFuture := currentTime.Add(2 * time.Hour)
	logTimestamp := *logEvent.InputLogEvent.Timestamp
	if logTimestamp.Before(logTimestampLimitInPast) || logTimestamp.After(logTimestampLimitInFuture) {
		err := errors.New("The log entry's timestamp is older than 14 days or more than 2 hours in the future.")
		logger.Error("Discard log entry with invalid timestamp.",
			zap.Error(err), zap.String("LogEventTimestamp", logTimestamp.String()), zap.String("CurrentTime", currentTime.String()))
		return err
	}
	return nil
}

// Calculate the log event payload bytes.
func (logEvent *Event) eventPayloadBytes() int {
	return len(*logEvent.InputLogEvent.Message) + perEventHeaderBytes
}

// eventBatch struct to represent a batch of log events.
type eventBatch struct {
	putSystemLogEventsInput *ecstcsnewservice.PutSystemLogEventsInput
	// The total bytes already in this log event batch.
	byteTotal int
	// Earliest timestamp recorded in this log event batch.
	minTimestamp time.Time
	// Latest timestamp recorded in this log event batch.
	maxTimestamp time.Time
}

// Create a new log event batch if needed.
func newEventBatch(key StreamKey) *eventBatch {
	return &eventBatch{
		putSystemLogEventsInput: &ecstcsnewservice.PutSystemLogEventsInput{
			LogGroupName:  aws.String(key.LogGroupName),
			LogStreamName: aws.String(key.LogStreamName),
			LogEvents:     make([]*ecstcsnewservice.LogEvent, 0, maxRequestEventCount)},
	}
}

func (batch eventBatch) exceedsLimit(nextByteTotal int) bool {
	return len(batch.putSystemLogEventsInput.LogEvents) == cap(batch.putSystemLogEventsInput.LogEvents) ||
		batch.byteTotal+nextByteTotal > maxEventPayloadBytes
}

// isActive checks whether the eventBatch spans more than 24 hours.
// Returns false if the condition does not match, and this batch should not be processed any further.
func (batch *eventBatch) isActive(logTimestamp time.Time) bool {
	if batch.minTimestamp.IsZero() || batch.maxTimestamp.IsZero() {
		// New log event batch.
		return true
	}
	if logTimestamp.Sub(batch.minTimestamp) > 24*time.Hour {
		return false
	}
	if batch.maxTimestamp.Sub(logTimestamp) > 24*time.Hour {
		return false
	}
	return true
}

func (batch *eventBatch) append(event *Event) {
	batch.putSystemLogEventsInput.LogEvents = append(batch.putSystemLogEventsInput.LogEvents, event.InputLogEvent)
	batch.byteTotal += event.eventPayloadBytes()
	if batch.minTimestamp.IsZero() || event.InputLogEvent.Timestamp.Before(batch.minTimestamp) {
		batch.minTimestamp = *event.InputLogEvent.Timestamp
	}
	if batch.maxTimestamp.IsZero() || event.InputLogEvent.Timestamp.After(batch.maxTimestamp) {
		batch.maxTimestamp = *event.InputLogEvent.Timestamp
	}
}

// Sort the log events based on the timestamp.
func (batch *eventBatch) sortLogEvents() {
	inputLogEvents := batch.putSystemLogEventsInput.LogEvents
	sort.Stable(ByTimestamp(inputLogEvents))
}

type ByTimestamp []*ecstcsnewservice.LogEvent

func (inputLogEvents ByTimestamp) Len() int {
	return len(inputLogEvents)
}

func (inputLogEvents ByTimestamp) Swap(i, j int) {
	inputLogEvents[i], inputLogEvents[j] = inputLogEvents[j], inputLogEvents[i]
}

func (inputLogEvents ByTimestamp) Less(i, j int) bool {
	return inputLogEvents[i].Timestamp.Before(*inputLogEvents[j].Timestamp)
}

// Pusher is created by log group and log stream
type Pusher interface {
	AddLogEntry(logEvent *Event) error
	ForceFlush() error
}

// Struct of logPusher implemented Pusher interface.
type logPusher struct {
	logger *zap.Logger
	// log group name of the current logPusher
	logGroupName *string
	// log stream name of the current logPusher
	logStreamName *string

	logEventBatch *eventBatch

	svcStructuredLog Client
	retryCnt         int
}

// NewPusher creates a logPusher instance
func NewPusher(streamKey StreamKey, retryCnt int,
	svcStructuredLog Client, logger *zap.Logger) Pusher {

	pusher := newLogPusher(streamKey, svcStructuredLog, logger)

	pusher.retryCnt = defaultRetryCount
	if retryCnt > 0 {
		pusher.retryCnt = retryCnt
	}

	return pusher
}

// Only create a logPusher, but not start the instance.
func newLogPusher(streamKey StreamKey,
	svcStructuredLog Client, logger *zap.Logger) *logPusher {
	pusher := &logPusher{
		logGroupName:     aws.String(streamKey.LogGroupName),
		logStreamName:    aws.String(streamKey.LogStreamName),
		svcStructuredLog: svcStructuredLog,
		logger:           logger,
	}
	pusher.logEventBatch = newEventBatch(streamKey)

	return pusher
}

// AddLogEntry Besides the limit specified by PutLogEvents API, there are some overall limit for the cloudwatchlogs
// listed here: http://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html
//
// Need to pay attention to the below 2 limits:
// Event size 256 KB (maximum). This limit cannot be changed.
// Batch size 1 MB (maximum). This limit cannot be changed.
func (p *logPusher) AddLogEntry(logEvent *Event) error {
	var err error
	if logEvent != nil {
		err = logEvent.Validate(p.logger)
		if err != nil {
			return err
		}
		prevBatch := p.addLogEvent(logEvent)
		if prevBatch != nil {
			err = p.pushEventBatch(prevBatch)
		}
	}
	return err
}

func (p *logPusher) ForceFlush() error {
	prevBatch := p.renewEventBatch()
	if prevBatch != nil {
		return p.pushEventBatch(prevBatch)
	}
	return nil
}

func (p *logPusher) pushEventBatch(req any) error {

	// http://docs.aws.amazon.com/goto/SdkForGoV1/logs-2014-03-28/PutLogEvents
	// The log events in the batch must be in chronological ordered by their
	// timestamp (the time the event occurred, expressed as the number of milliseconds
	// since Jan 1, 1970 00:00:00 UTC).
	logEventBatch := req.(*eventBatch)
	logEventBatch.sortLogEvents()
	putSystemLogEventsInput := logEventBatch.putSystemLogEventsInput

	startTime := time.Now()

	err := p.svcStructuredLog.PutSystemLogEvents(putSystemLogEventsInput, p.retryCnt)

	if err != nil {
		return err
	}

	p.logger.Debug("logpusher: publish log events successfully.",
		zap.Int("NumOfLogEvents", len(putSystemLogEventsInput.LogEvents)),
		zap.Float64("LogEventsSize", float64(logEventBatch.byteTotal)/float64(1024)),
		zap.Int64("Time", time.Since(startTime).Nanoseconds()/int64(time.Millisecond)))

	return nil
}

func (p *logPusher) addLogEvent(logEvent *Event) *eventBatch {
	if logEvent == nil {
		return nil
	}

	var prevBatch *eventBatch
	currentBatch := p.logEventBatch
	if currentBatch.exceedsLimit(logEvent.eventPayloadBytes()) || !currentBatch.isActive(*logEvent.InputLogEvent.Timestamp) {
		prevBatch = currentBatch
		currentBatch = newEventBatch(StreamKey{
			LogGroupName:  *p.logGroupName,
			LogStreamName: *p.logStreamName,
		})
	}
	currentBatch.append(logEvent)
	p.logEventBatch = currentBatch

	return prevBatch
}

func (p *logPusher) renewEventBatch() *eventBatch {

	var prevBatch *eventBatch
	if len(p.logEventBatch.putSystemLogEventsInput.LogEvents) > 0 {
		prevBatch = p.logEventBatch
		p.logEventBatch = newEventBatch(StreamKey{
			LogGroupName:  *p.logGroupName,
			LogStreamName: *p.logStreamName,
		})
	}

	return prevBatch
}

// A Pusher that is able to send events to multiple streams.
type multiStreamPusher struct {
	logStreamManager LogStreamManager
	client           Client
	pusherMap        map[StreamKey]Pusher
	logger           *zap.Logger
}

func newMultiStreamPusher(logStreamManager LogStreamManager, client Client, logger *zap.Logger) *multiStreamPusher {
	return &multiStreamPusher{
		logStreamManager: logStreamManager,
		client:           client,
		logger:           logger,
		pusherMap:        make(map[StreamKey]Pusher),
	}
}

func (m *multiStreamPusher) AddLogEntry(event *Event) error {
	if err := m.logStreamManager.InitStream(event.StreamKey); err != nil {
		return err
	}

	var pusher Pusher
	var ok bool

	if pusher, ok = m.pusherMap[event.StreamKey]; !ok {
		pusher = NewPusher(event.StreamKey, 1, m.client, m.logger)
		m.pusherMap[event.StreamKey] = pusher
	}

	return pusher.AddLogEntry(event)
}

func (m *multiStreamPusher) ForceFlush() error {
	var errs []error

	for _, val := range m.pusherMap {
		err := val.ForceFlush()
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) != 0 {
		return errors.Join(errs...)
	}

	return nil
}

// Factory for a Pusher that has capability of sending events to multiple log streams
type MultiStreamPusherFactory interface {
	CreateMultiStreamPusher() Pusher
}

type multiStreamPusherFactory struct {
	logStreamManager LogStreamManager
	logger           *zap.Logger
	client           Client
}

// Creates a new MultiStreamPusherFactory
func NewMultiStreamPusherFactory(logStreamManager LogStreamManager, client Client, logger *zap.Logger) MultiStreamPusherFactory {
	return &multiStreamPusherFactory{
		logStreamManager: logStreamManager,
		client:           client,
		logger:           logger,
	}
}

// Factory method to create a Pusher that has support to sending events to multiple log streams
func (msf *multiStreamPusherFactory) CreateMultiStreamPusher() Pusher {
	return newMultiStreamPusher(msf.logStreamManager, msf.client, msf.logger)
}

// Manages the creation of streams
type LogStreamManager interface {
	// Initialize a stream so that it can receive logs
	// This will make sure that the stream exists and if it does not exist,
	// It will create one. Implementations of this method MUST be safe for concurrent use.
	InitStream(streamKey StreamKey) error
}

type logStreamManager struct {
	logStreamMutex sync.Mutex
	streams        map[StreamKey]bool
	client         Client
}

func NewLogStreamManager(svcStructuredLog Client) LogStreamManager {
	return &logStreamManager{
		client:  svcStructuredLog,
		streams: make(map[StreamKey]bool),
	}
}

func (lsm *logStreamManager) InitStream(streamKey StreamKey) error {
	//if _, ok := lsm.streams[streamKey]; !ok {
	//	lsm.logStreamMutex.Lock()
	//	defer lsm.logStreamMutex.Unlock()
	//
	//	if _, ok := lsm.streams[streamKey]; !ok {
	//		err := lsm.client.CreateStream(&streamKey.LogGroupName, &streamKey.LogStreamName)
	//		lsm.streams[streamKey] = true
	//		return err
	//	}
	//}
	return nil
	// does not do anything if stream already exists
}
