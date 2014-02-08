/*
 * upstream.h
 *
 *  Created on: Feb 7, 2014
 *      Author: cebka
 */

#ifndef UPSTREAM_H_
#define UPSTREAM_H_

#include <time.h>
#include <stdio.h>

/**
 * @file upstream.h
 * The basic macros to define upstream objects
 */

#ifndef upstream_fatal
#define upstream_fatal(msg) do { perror (msg); exit (-1); } while (0)
#endif

#ifndef upstream_malloc
#define upstream_malloc(size) malloc (size)
#endif

#ifndef upstream_free
#define upstream_free(size, ptr) free (ptr)
#endif

struct upstream_entry_s;
struct upstream_common_data {
	struct upstream_entry_s *upstreams;
	unsigned int allocated_nelts;
	unsigned int nelts;
	unsigned int alive;
};

typedef struct upstream_entry_s {
	unsigned short errors;						/**< errors for this upstream 	*/
	unsigned short dead;
	unsigned short priority;
	unsigned short weight;
	time_t time;								/**< time of marking 			*/
	void *parent;								/**< parent object				*/
	struct upstream_common_data *common;		/**< common data				*/
	void *next;									/**< link to the next			*/
} upstream_entry_t;

/*
 * Here we define some reasonable defaults:
 * if an upstream has more than `UPSTREAM_MAX_ERRORS` in the period of time
 * of `UPSTREAM_ERROR_TIME` then we shut it down for `UPSTREAM_REVIVE_TIME`.
 * In this particular case times are 10 seconds for 10 errors and revive in
 * 30 seconds.
 */
#ifndef UPSTREAM_REVIVE_TIME
#define UPSTREAM_REVIVE_TIME 30
#endif
#ifndef UPSTREAM_ERROR_TIME
#define UPSTREAM_ERROR_TIME 10
#endif
#ifndef UPSTREAM_MAX_ERRORS
#define UPSTREAM_MAX_ERRORS 10
#endif

#define UPSTREAM_FAIL(u, now) do {											\
	if ((u)->up.time != 0) {												\
		(u)->up.errors ++;													\
	}																		\
	else {																	\
		(u)->up.time = now;													\
		(u)->up.dead = 1;													\
		(u)->up.common->alive --;											\
	}																		\
} while (0)

#define UPSTREAM_OK(u) do {													\
	(u)->up.errors = 0;														\
} while (0)

#define UPSTREAM_ADD(head, u, priority) do {								\
	if (head == NULL) {														\
		struct upstream_common_data *cd;									\
		cd = upstream_malloc (sizeof (struct upstream_common_data));		\
		if (cd == NULL) {													\
			upstream_fatal ("malloc failed");								\
		}																	\
		cd->upstreams = upstream_malloc (sizeof (upstream_entry_t) * 8);	\
		if (cd == NULL) {													\
			upstream_fatal ("malloc failed");								\
		}																	\
		cd->allocated_nelts = 8;											\
		cd->nelts = 1;														\
		cd->alive = 1;														\
		cd->upstreams[0] = (u);												\
		(u)->up.common = cd;												\
	}																		\
	else {																	\
		struct upstream_common_data *cd = (head)->up.common;				\
		(u)->up.common = cd;												\
		if (cd->nelts == cd->allocated_nelts) {								\
			struct upstream_entry_s *nup;									\
			nup = upstream_malloc (sizeof (upstream_entry_t) * cd->nelts * 2);	\
			if (nup == NULL) {												\
				upstream_fatal ("malloc failed");							\
			}																\
			memcpy (nup, cd->upstreams, cd->nelts * sizeof (upstream_entry_t));	\
			upstream_free (cd->nelts * sizeof (upstream_entry_t), cd->upstreams);	\
			cd->upstreams = nup;											\
			cd->allocated_nelts *= 2;										\
		}																	\
		cd->upstreams[cd->nelts++] = (u);									\
		cd->alive ++;														\
	}																		\
	(u)->up.next = (head);													\
	(head) = (u);															\
	(u)->up.priority = (u)->up.weight = (priority);							\
	(u)->up.time = 0;														\
	(u)->up.errors = 0;														\
	(u)->up.alive = 1;														\
	(u)->up.parent = (u);													\
} while (0)

#define UPSTREAM_FOREACH(head, u) for ((u) = (head); (u) != NULL; (u) = (u)->up.next)

#define UPSTREAM_REVIVE_ALL(head) do {										\
	__typeof(head) elt = (head);											\
	while (elt != NULL) {													\
		elt->up.dead = 0;													\
		elt->up.errors = 0;													\
		elt = elt->up.next;													\
	}																		\
	(head)->up.common->alive = (head)->up.common->elts;						\
} while (0)

#define UPSTREAM_RESCAN(head, now) do {										\
	__typeof(head) elt = (head);											\
	if ((head)->up.common->alive == 0) {									\
	  UPSTREAM_REVIVE_ALL((head));											\
	}																		\
	else {																	\
		while (elt != NULL) {												\
			if (elt->up.dead) {												\
				if ((now) - elt->up.time >= UPSTREAM_REVIVE_TIME) {			\
					elt->up.dead = 0;										\
					elt->up.errors = 0;										\
					elt->up.weight = elt->up.priority;						\
					(head)->up.common->alive ++;							\
				}															\
			}																\
			else {															\
				if ((now) - elt->up.time >= UPSTREAM_ERROR_TIME &&			\
						elt->up.errors >= UPSTREAM_MAX_ERRORS) {			\
					elt->up.dead = 1;										\
					elt->up.time = now;										\
					(head)->up.common->alive --;							\
				}															\
				else {														\
				  (head)->up.common->alive ++;								\
				}															\
			}																\
			elt = elt->up.next;												\
		}																	\
	}																		\
} while (0)

#define UPSTREAM_SELECT_ROUND_ROBIN(head, selected) do {					\
	__typeof(head) elt = (head));											\
	selected = NULL;														\
	int alive = 0;															\
	unsigned max_weight = 0;												\
	if ((head)->up.common->alive == 0){ 									\
		UPSTREAM_REVIVE_ALL(head);											\
	}																		\
	while (elt != NULL) {													\
		if (!elt->dead) {													\
			if (elt->up.weight > max_weight) {								\
				max_weight = elt->up.weight;								\
				selected = elt;												\
			}																\
			alive ++;														\
		}																	\
		elt = elt->up.next;													\
	}																		\
	if (max_weight == 0) {													\
		elt = (head);														\
		while (elt != NULL) {												\
			if (!elt->dead) {												\
				if (elt->up.priority > max_weight) {						\
					max_weight = elt->up.priority;							\
					selected = elt;											\
				}															\
			}																\
			elt = elt->up.next;												\
		}																	\
	}																		\
} while (0)

#endif /* UPSTREAM_H_ */
