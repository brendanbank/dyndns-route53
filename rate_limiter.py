from datetime import datetime, timedelta, timezone


class RateLimiter:
    """Database-backed rate limiter. Shared across all gunicorn workers."""

    def record_request(self, user_id):
        from models import db, RateLimitEvent
        ev = RateLimitEvent(user_id=user_id, created_at=datetime.now(timezone.utc))
        db.session.add(ev)
        # Prune entries older than 1 hour to keep the table small
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        RateLimitEvent.query.filter(RateLimitEvent.created_at < cutoff).delete()
        db.session.commit()

    def is_rate_limited(self, user_id, per_minute, per_hour):
        from models import RateLimitEvent
        now = datetime.now(timezone.utc)

        # Check per-minute limit
        minute_ago = now - timedelta(minutes=1)
        recent_minute = RateLimitEvent.query.filter(
            RateLimitEvent.user_id == user_id,
            RateLimitEvent.created_at > minute_ago,
        ).count()
        if recent_minute >= per_minute:
            return True

        # Check per-hour limit
        hour_ago = now - timedelta(hours=1)
        recent_hour = RateLimitEvent.query.filter(
            RateLimitEvent.user_id == user_id,
            RateLimitEvent.created_at > hour_ago,
        ).count()
        if recent_hour >= per_hour:
            return True

        return False


# Module-level singleton
rate_limiter = RateLimiter()


def check_rate_limit(user):
    """Check if user is rate limited. Returns True if request should be blocked."""
    from models import RateLimitConfig

    # Check per-user override first
    user_config = RateLimitConfig.query.filter_by(user_id=user.id).first()
    if user_config:
        per_minute = user_config.requests_per_minute
        per_hour = user_config.requests_per_hour
    else:
        # Fall back to global config
        global_config = RateLimitConfig.query.filter_by(is_global=True).first()
        if global_config:
            per_minute = global_config.requests_per_minute
            per_hour = global_config.requests_per_hour
        else:
            per_minute = 30
            per_hour = 500

    return rate_limiter.is_rate_limited(user.id, per_minute, per_hour)
