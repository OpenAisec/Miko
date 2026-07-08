#ifndef SDB_HEAP_H
#define SDB_HEAP_H 1

#ifdef __cplusplus
extern "C" {
#endif

typedef void *(*SdbHeapRealloc)(void *data, void *ptr, size_t size);
typedef void (*SdbHeapFini)(void *data);

// global heap apis
typedef struct sdb_global_heap_t {
	SdbHeapRealloc realloc;
	// SdbHeapInit init;
	SdbHeapFini fini;
	void *data;
} SdbGlobalHeap;

SDB_API SdbGlobalHeap *sdb_gh (void);

static inline void sdb_gh_use(const SdbGlobalHeap *gh) {
	SdbGlobalHeap *gheap = sdb_gh ();
	if (gh) {
		memcpy (gheap, gh, sizeof (SdbGlobalHeap));
	} else {
		memset (gheap, 0, sizeof (SdbGlobalHeap));
	}
}

static inline void sdb_gh_fini(void) {
	SdbGlobalHeap *gheap = sdb_gh ();
	if (gheap->fini) {
		gheap->fini (gheap->data);
	}
}

static inline void *sdb_gh_malloc(size_t size) {
	SdbGlobalHeap *gheap = sdb_gh ();
	if (gheap->realloc) {
		void *ptr = gheap->realloc (gheap->data, NULL, size);
//		eprintf ("malloc %p\n" , ptr);
		return ptr;
	}
	return malloc (size);
}

static inline void *sdb_gh_realloc(void *ptr, size_t size) {
	SdbGlobalHeap *gheap = sdb_gh ();
	if (gheap->realloc) {
		return gheap->realloc (gheap->data, ptr, size);
	}
	return realloc (ptr, size);
}

static inline void sdb_gh_free(void *ptr) {
	SdbGlobalHeap *gheap = sdb_gh ();
	if (!ptr) {
		return;
	}
	if (gheap->realloc) {
// 		eprintf ("free ptr %p\n" , ptr);
		gheap->realloc (gheap->data, ptr, 0);
	} else {
		free (ptr);
	}
}

static inline void *sdb_gh_calloc(size_t count, size_t size) {
	size_t total = count * size; // TODO: detect overflow
	void *res = sdb_gh_malloc (total);
	if (res) {
		memset (res, 0, total);
	}
	return res;
}

#ifdef __cplusplus
}
#endif

#endif
