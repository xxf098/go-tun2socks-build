package tun2socks

import (
	vapplog "v2ray.com/core/app/log"
	vcommon "v2ray.com/core/common"
	vcommonlog "v2ray.com/core/common/log"
)

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

func registerLogService(logService LogService) {
	if logService != nil {
		vcommon.Must(vapplog.RegisterHandlerCreator(vapplog.LogType_Console, func(lt vapplog.LogType,
			options vapplog.HandlerCreatorOptions) (vcommonlog.Handler, error) {
			return vcommonlog.NewLogger(createLogWriter(logService)), nil
		}))
	}
}
