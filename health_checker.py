import dns.resolver

from lib import log

scheduler = None


def run_health_checks(app):
    """Resolve all tracked hostnames and compare against last known IPs."""
    with app.app_context():
        from models import db, Hostname, HealthCheck, HealthCheckConfig

        config = HealthCheckConfig.query.first()
        if config and not config.enabled:
            return

        # Clear previous results — only keep the latest run
        HealthCheck.query.delete()

        hostnames = Hostname.query.filter(
            (Hostname.last_ip_v4.isnot(None)) | (Hostname.last_ip_v6.isnot(None))
        ).all()

        for hn in hostnames:
            for expected_ip, rtype in [(hn.last_ip_v4, 'A'), (hn.last_ip_v6, 'AAAA')]:
                if not expected_ip:
                    continue

                actual_ip = None
                status = 'error'
                detail = None

                try:
                    answers = dns.resolver.resolve(hn.name, rtype)
                    actual_ip = answers[0].address
                    if actual_ip == expected_ip:
                        status = 'ok'
                    else:
                        status = 'mismatch'
                        detail = f'Expected {expected_ip}, got {actual_ip}'
                except dns.resolver.NXDOMAIN:
                    status = 'missing'
                    detail = 'Domain does not exist'
                except dns.resolver.NoAnswer:
                    status = 'missing'
                    detail = f'No {rtype} record found'
                except dns.resolver.NoNameservers:
                    status = 'error'
                    detail = 'No nameservers available'
                except Exception as e:
                    status = 'error'
                    detail = str(e)

                if status == 'mismatch':
                    log.warning(f'Health check MISMATCH: {hn.name} {rtype} expected {expected_ip}, got {actual_ip}')
                elif status == 'missing':
                    log.warning(f'Health check MISSING: {hn.name} {rtype} expected {expected_ip}, {detail}')
                elif status == 'error':
                    log.error(f'Health check ERROR: {hn.name} {rtype} {detail}')

                hc = HealthCheck(
                    hostname=hn.name,
                    expected_ip=expected_ip,
                    actual_ip=actual_ip,
                    record_type=rtype,
                    status=status,
                    detail=detail,
                )
                db.session.add(hc)

        db.session.commit()
        log.info(f'Health check completed for {len(hostnames)} hostname(s)')


def init_health_checker(app):
    """Start the background scheduler for periodic health checks."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        log.warning('APScheduler not installed — health checks disabled. Install with: pip install APScheduler')
        return

    from models import HealthCheckConfig

    global scheduler

    with app.app_context():
        config = HealthCheckConfig.query.first()
        if config and not config.enabled:
            log.info('Health checks are disabled in configuration')
            return
        interval = config.check_interval_minutes if config else 15

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_health_checks,
        'interval',
        minutes=interval,
        args=[app],
        max_instances=1,
        id='health_check',
    )
    scheduler.start()
    log.info(f'Health checker started (interval: {interval} minutes)')


def reschedule_health_checker(app):
    """Update the scheduler interval from current config."""
    global scheduler
    if scheduler is None:
        init_health_checker(app)
        return

    from models import HealthCheckConfig

    with app.app_context():
        config = HealthCheckConfig.query.first()

    if config and not config.enabled:
        if scheduler.running:
            scheduler.pause_job('health_check')
        return

    interval = config.check_interval_minutes if config else 15

    try:
        scheduler.reschedule_job('health_check', trigger='interval', minutes=interval)
        scheduler.resume_job('health_check')
    except Exception:
        init_health_checker(app)
