class ModuleRegistry:
    _modules = {}

    @classmethod
    def register(cls, module_class):
        cls._modules[module_class.name] = module_class
        return module_class

    @classmethod
    def get(cls, name):
        return cls._modules.get(name)

    @classmethod
    def by_category(cls, category):
        return {k: v for k, v in cls._modules.items() if v.category == category}

    @classmethod
    def all(cls):
        return dict(cls._modules)


def load_all():
    from obbyism.modules.recon import whois, dns, headers, subdomains  # noqa: F401
    from obbyism.modules.scan import ports, services, sweep  # noqa: F401
    from obbyism.modules.vuln import ssl_check, security_headers, directories  # noqa: F401
