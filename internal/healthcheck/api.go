package healthcheck

import routing "github.com/garaekz/ozzo-routing"

// RegisterHandlers registers the handlers that perform healthchecks.
func RegisterHandlers(r *routing.Router, version string) {
	r.To("GET,HEAD", "/healthcheck", healthcheck(version))
}

// healthcheck responds to a healthcheck request.
func healthcheck(version string) routing.Handler {
	return func(c *routing.Context) error {
		return c.Write("OK " + version)
	}
}
