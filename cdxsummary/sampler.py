import hashlib
import heapq


class BaseSampler():
    def __init__(self, size=0, valid=lambda item: True, transform=lambda item: item, seed="cdxsummary"):
        self._size = size
        self._samples = [None] * size
        self._processed = 0
        self._valid = valid
        self._transform = transform
        self._seed = seed.encode("utf-8") if isinstance(seed, str) else bytes(seed)


    def __call__(self, item):
        pass


    def samples(self):
        return filter(lambda sample: sample is not None, self._samples)


    def set_samples(self, samples):
        """Restore samples produced elsewhere (e.g. when loading a JSON report)."""
        self._samples = list(samples)
        self._size = len(self._samples)
        self._seen = set()


    def __str__(self):
        return str(self.samples())


class DynamicRandomStreamSampler(BaseSampler):
    """Order-independent, reproducible bounded sample of a stream.

    Every valid item is hashed together with a fixed seed and the item keeps
    the slots occupied by the smallest ``size`` hashes seen so far. Because
    the hash depends only on the item (not on its position) and ties are
    broken by the item itself, the result is the same for any ordering of the
    input, including interleaved shards, and stays stable across runs.
    Repeated occurrences of the same transformed item collapse into one
    sample.
    """

    def _digest(self, key):
        payload = self._seed + repr(key).encode("utf-8")
        return int.from_bytes(hashlib.blake2b(payload, digest_size=8).digest(), "big")


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._seen = set()
        # Max-heap of (digest, key) emulated with negated digests so the
        # largest selected digest sits at index 0 and can be evicted.
        self._heap = []


    def __call__(self, item):
        if not self._valid(item):
            return
        key = self._transform(item)
        if key in self._seen:
            return
        self._seen.add(key)
        self._processed += 1
        if self._size <= 0:
            return
        digest = self._digest(key)
        if len(self._heap) < self._size:
            heapq.heappush(self._heap, (-digest, key))
        elif digest < -self._heap[0][0]:
            heapq.heapreplace(self._heap, (-digest, key))


    def samples(self):
        ordered = sorted([(-neg_digest, key) for neg_digest, key in self._heap])
        self._samples = [key for _, key in ordered]
        return iter(self._samples)


    def set_samples(self, samples):
        self._samples = list(samples)
        self._size = len(self._samples)
        self._seen = set(self._samples)
        self._processed = len(self._samples)
        self._heap = [(-self._digest(key), key) for key in self._samples]
        heapq.heapify(self._heap)
