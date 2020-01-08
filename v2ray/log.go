package v2ray
import (
	"log"
	"os"

	vlog "v2ray.com/core/common/log"
)

type consoleLogWriter struct {
	logger *log.Logger
}

func (w *consoleLogWriter) Write(s string) error {
	w.logger.Print(s)
	return nil
}

func (w *consoleLogWriter) Close() error {
	return nil
}

func CreateStdoutLogWriter() vlog.WriterCreator {
	return func() vlog.Writer {
		return &consoleLogWriter{
			logger: log.New(os.Stdout, "", 0)}
	}
}