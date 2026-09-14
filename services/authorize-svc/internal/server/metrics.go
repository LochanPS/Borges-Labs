package server

import "net/http"

// handleMetrics serves the Prometheus text exposition at GET /metrics (TRD §18):
// verdict distribution, decision-latency histogram, and rate-limit rejections. It is
// unauthenticated for scraping and should be restricted at the network layer in
// production (the same posture Prometheus /metrics endpoints normally take).
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metrics == nil {
		s.writeProblem(w, r, http.StatusServiceUnavailable, codeInternal,
			"Metrics unavailable", "Metrics are not enabled on this instance.", nil)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	s.metrics.WriteText(w)
}
