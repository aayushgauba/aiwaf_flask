from .db_models import db, WhitelistedIP, BlacklistedIP, Keyword

# Flask-adapted storage (stub)
class ExemptionStore:
    _exempt_ips = set()
    def is_exempted(self, ip):
        return ip in self._exempt_ips
    def add_exempt(self, ip):
        self._exempt_ips.add(ip)

def get_exemption_store():
    return ExemptionStore()

class KeywordStore:
    def add_keyword(self, kw):
        add_keyword(kw)
    def get_top_keywords(self, n=10):
        return get_top_keywords(n)

def get_keyword_store():
    return KeywordStore()

def is_ip_whitelisted(ip):
    return WhitelistedIP.query.filter_by(ip=ip).first() is not None

def add_ip_whitelist(ip):
    if not is_ip_whitelisted(ip):
        db.session.add(WhitelistedIP(ip=ip))
        db.session.commit()

def is_ip_blacklisted(ip):
    return BlacklistedIP.query.filter_by(ip=ip).first() is not None

def add_ip_blacklist(ip, reason=None):
    if not is_ip_blacklisted(ip):
        db.session.add(BlacklistedIP(ip=ip, reason=reason))
        db.session.commit()

def remove_ip_blacklist(ip):
    entry = BlacklistedIP.query.filter_by(ip=ip).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()

def add_keyword(kw):
    if not Keyword.query.filter_by(keyword=kw).first():
        db.session.add(Keyword(keyword=kw))
        db.session.commit()

def get_top_keywords(n=10):
    return [k.keyword for k in Keyword.query.limit(n).all()]
