package tacsv2

import (
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/ohsoo/tacsv2/model/ecstcsnewservice"
	"go.uber.org/zap"
)

const (
	// This is the retry count, the total attempts will be at most retry count + 1.
	defaultRetryCount          = 1
	errCodeThrottlingException = "ThrottlingException"
)

type tacsAPI interface {
	PutSystemLogEvents(input *ecstcsnewservice.PutSystemLogEventsInput) (*ecstcsnewservice.PutSystemLogEventsOutput, error)
}

type Client struct {
	//svc cloudwatchlogsiface.CloudWatchLogsAPI
	svc    tacsAPI
	logger *zap.Logger
}

// NewClient creates a CWL Client.
func NewClient(logger *zap.Logger, logGroupName string, logStreamName string, awsConfig *aws.Config, sess *session.Session) *Client {
	client := ecstcsnewservice.New(sess, awsConfig)
	return newTACSClient(client, logger, logGroupName, logStreamName)
}

// Create a log client based on the tacs v2 client.
func newTACSClient(svc tacsAPI, logger *zap.Logger, logGroupName string, logStreamName string) *Client {
	logClient := &Client{
		svc:    svc,
		logger: logger,
	}
	return logClient
}

// PutSystemLogEvents mainly handles possible errors returned from server side, and retries them if necessary.
func (client *Client) PutSystemLogEvents(input *ecstcsnewservice.PutSystemLogEventsInput, retryCnt int) error {
	var response *ecstcsnewservice.PutSystemLogEventsOutput
	var err error
	// Possible exceptions from TACS are [...]
	for i := 0; i <= retryCnt; i++ {
		response, err = client.svc.PutSystemLogEvents(input)
		if err != nil {
			var awsErr awserr.Error
			if !errors.As(err, &awsErr) {
				client.logger.Error("Cannot cast PutSystemLogEvents error into awserr.Error.", zap.Error(err))
				return err
			}
			switch e := awsErr.(type) {
			case *ecstcsnewservice.InvalidParameterException:
				client.logger.Error("tacs_client: Error occurs in PutSystemLogEvents, will not retry the request", zap.Error(e), zap.String("LogGroupName", *input.LogGroupName), zap.String("LogStreamName", *input.LogStreamName))
				return err
			case *ecstcsnewservice.ServerException: // Retry request if OperationAbortedException happens
				client.logger.Warn("tacs_client: Error occurs in PutSystemLogEvents, will retry the request", zap.Error(e))
				return err
			default:
				// Drop request if ThrottlingException happens.
				if awsErr.Code() == errCodeThrottlingException {
					client.logger.Warn("tacs_client: Throttling error in PutSystemLogEvents.", zap.Error(awsErr), zap.String("LogGroupName", *input.LogGroupName), zap.String("LogStreamName", *input.LogStreamName))
					return err
				}
				client.logger.Error("tacs_client: Error occurs in PutSystemLogEvents", zap.Error(awsErr))
				return err
			}

		}

		if response != nil {
			// TBD. Response is always empty as of current implementation.
		}
	}
	if err != nil {
		client.logger.Error("All retries failed for PutSystemLogEvents. Drop this request.", zap.Error(err))
	}
	return err
}
