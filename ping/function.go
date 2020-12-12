package ping

type RunPing func(int, string, chan LatencyResult) error
