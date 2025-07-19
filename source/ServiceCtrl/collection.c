/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2023 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
**************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "collection.h"


queue_t *queue_create   (void)
{
    queue_t *q;

    q = (queue_t *)malloc(sizeof(queue_t));
    if (q == NULL) {
        return NULL;
    }
    memset(q, 0, sizeof(queue_t));
    return q;
}

int8_t     queue_push      (queue_t *q, void *data)
{
    element_t *e, *tmp;
    e = (element_t *)malloc(sizeof(element_t));
    if (e == NULL) {
        return -1;
    }
    memset(e, 0, sizeof(element_t));
    e->data = data;
    if (q->head == NULL) {
        q->head = e;
    } else {
        tmp = q->head;
        q->head = e;
        e->next = tmp;
    }
    q->count++;
    return 0;
}

void    *queue_pop      (queue_t *q)
{
    element_t *e, *tmp = NULL;
    void *data;
    e = q->head;
    if (e == NULL) {
        return NULL;
    }
    while (e->next != NULL) {
        tmp = e;
        e = e->next;
    }

    data = e->data;
    if (tmp != NULL) {
        tmp->next = NULL;
    } else {
        q->head = NULL;
    }
    free(e);
    q->count--;
    return data;
}

void     *queue_remove    (queue_t *q, uint32_t index)
{
    element_t    *e, *tmp = NULL;
    void *data;
    uint32_t i = 0;

    if (index >= queue_count(q)) {
        return NULL;
    }
    e = q->head;
    if (e == NULL) {
        return NULL;
    }
    while (i < index) {
        tmp = e;
        e = e->next;
        i++;
    }
    if (tmp == NULL) {
        q->head = e->next;
    } else {
        tmp->next = e->next;
    }
    data = e->data;
    free(e);
    q->count--;
    return data;
}

void    *queue_peek  (queue_t *q, uint32_t index)
{
    element_t    *e;
    uint32_t i = 0;

    if (index >= queue_count(q)) {
        return NULL;
    }
    e = q->head;
    if (e == NULL) {
        return NULL;
    }
    while ((i < index) && (e != NULL)) {
        e = e->next;
        i++;
    }
    if (e) {
        return e->data;
    }
    return NULL;
}

uint32_t queue_count    (queue_t *q)
{
    if (q == NULL) {
        return 0;
    } else {
        return q->count;
    }
}

void    queue_destroy   (queue_t *q)
{
    element_t    *e, *tmp;
    e = q->head;
    while (e != NULL) {
        tmp = e->next;
        if (e->data != NULL) {
            free(e->data);
        }
        free(e);
        e = tmp;
    }
    free(q);
}
