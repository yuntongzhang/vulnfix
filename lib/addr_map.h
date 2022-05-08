struct map_s
{
  void *start;
  void *end;
  bool readable;
  bool writable;
  struct map_s *next;
};
typedef struct map_s MAP;

extern MAP *map;

void clean_up_address_map();
void build_address_map();
bool is_addr_writable(void *addr);
bool is_addr_readable(void *addr);
bool is_addr_accessable(void *addr);
