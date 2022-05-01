from pyroute2 import IPRoute


class IPR:
    # Singelton for IPRoute
    ipr: IPRoute

    def __enter__(self):
        IPR.ipr = IPRoute()
        return self

    def __exit__(self, _type, _value, _traceback):
        IPR.ipr.close()
