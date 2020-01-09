package tun2socks

import vcommonlog "v2ray.com/core/common/log"

type LogService interface {
	WriteLog(s string) error
}

type logWriter struct {
	logger *LogService
}

func (w *logWriter) Write(s string) error {
	(*w.logger).WriteLog(s)
	return nil
}

func (w *logWriter) Close() error {
	return nil
}

func createLogWriter(logService LogService) vcommonlog.WriterCreator {
	return func() vcommonlog.Writer {
		return &logWriter{
			logger: &logService,
		}
	}
}
