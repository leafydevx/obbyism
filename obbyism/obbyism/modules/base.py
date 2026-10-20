import time


class BaseModule:
    name = ""
    description = ""
    category = ""

    def __init__(self, session, output):
        self.session = session
        self.output = output

    def run(self, target, **kwargs):
        raise NotImplementedError

    def execute(self, target, **kwargs):
        self.output.header(f"{self.description}")
        self.output.info(f"Target: {target}")
        start = time.time()
        try:
            results = self.run(target, **kwargs)
            elapsed = time.time() - start
            self.output.info(f"Completed in {elapsed:.1f}s")
            if results is not None:
                self.session.add_result(self.name, results)
            return results
        except KeyboardInterrupt:
            self.output.warning("Module interrupted by user")
            return None
        except Exception as e:
            self.output.error(f"Module error: {e}")
            return None
