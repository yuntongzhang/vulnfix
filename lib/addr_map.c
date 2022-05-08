#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>

#include "addr_map.h"


MAP *map = NULL;

void clean_up_address_map()
{
  assert(map != NULL);
  MAP *prev = NULL;
  while (map != NULL)
  {
    prev = map;
    map = map->next;
    free(prev);
  }
  map = NULL; // just leak them
}

void build_address_map()
{
  if (map != NULL)
    clean_up_address_map();
  FILE *fp = fopen("/proc/self/maps", "r");
  char line[1000] = {0};
  void *start, *end;
  char flags[10] = {0};
  while (fgets(line, sizeof(line), fp))
  {
    sscanf(line, "%p-%p %s", &start, &end, flags);
    MAP *new_entry = (MAP *)malloc(sizeof(MAP));
    new_entry->start = start;
    new_entry->end = end;
    new_entry->writable = false;
    new_entry->readable = false;
    new_entry->next = map;
    map = new_entry;
    if (flags[0] == 'r')
      new_entry -> readable = true;
    if (flags[1] == 'w')
      new_entry -> writable = true;
  }
  fclose(fp);
}


bool is_addr_writable(void *addr)
{
  MAP *tmp = map;
  while (tmp)
  {
    if (addr >= tmp->start && addr <= tmp->end && tmp->writable)
      return true;
    tmp = tmp->next;
  }
  return false;
}


bool is_addr_readable(void *addr)
{
  MAP *tmp = map;
  while (tmp)
  {
    if (addr >= tmp->start && addr <= tmp->end && tmp->readable)
      return true;
    tmp = tmp->next;
  }
  return false;
}


bool is_addr_accessable(void *addr)
{
  return is_addr_writable(addr) || is_addr_readable(addr);
}
