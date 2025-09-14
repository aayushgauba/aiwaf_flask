from .storage import is_ip_blacklisted, add_ip_blacklist, remove_ip_blacklist

# Flask-adapted BlacklistManager
class BlacklistManager:
    @classmethod
    def is_blocked(cls, ip):
        return is_ip_blacklisted(ip)
    @classmethod
    def block(cls, ip, reason=None):
        add_ip_blacklist(ip, reason)
    @classmethod
    def unblock(cls, ip):
        remove_ip_blacklist(ip)
