#include <Python.h>

#define PACKAGE "bfdpie"
#define PACKAGE_VERSION "0.1"

#include <bfd.h>
#include <dis-asm.h>
#define DEBUG(format, ...)
//#define DEBUG(format, ...) printf("DEBUG: "format, __VA_ARGS__)
#define DISASSEMBLER_OPTIONS  

typedef struct
{
  char *buffer;
  size_t pos;
  size_t alloc;

} SFILE;

typedef struct
{
   char arch_name[128];

   // the -M<...> flag
   char disasm_options[128];

   enum bfd_endian endianess;
} arch_t;

static arch_t archs[] = {
   {"i386",             "intel",          BFD_ENDIAN_LITTLE},
   {"i386:x86-64",      "intel",          BFD_ENDIAN_LITTLE},
   {"arm",              "no-force-thumb", BFD_ENDIAN_LITTLE},
   {"arm",              "force-thumb",    BFD_ENDIAN_LITTLE},
   {"arm",              "no-force-thumb", BFD_ENDIAN_BIG},
   {"arm",              "force-thumb",    BFD_ENDIAN_BIG},
   {"aarch64",          "",               BFD_ENDIAN_LITTLE},
   {"aarch64",          "",               BFD_ENDIAN_BIG},
   {"mips",             "",               BFD_ENDIAN_BIG},
   {"mips",             "",               BFD_ENDIAN_LITTLE},
   {"mips",             "mips64",         BFD_ENDIAN_BIG},
   {"mips",             "mips64",         BFD_ENDIAN_LITTLE},
   {"powerpc:common",   "32",             BFD_ENDIAN_BIG},
   {"powerpc:common64", "64",             BFD_ENDIAN_BIG},
   {"sparc",            "",               BFD_ENDIAN_BIG},
   {"sparc:v9",         "",               BFD_ENDIAN_BIG},
   {"sh4",              "",               BFD_ENDIAN_LITTLE},
   {"sh4",              "",               BFD_ENDIAN_BIG},
   {"alpha:ev4",        "",               BFD_ENDIAN_BIG},
   {"crisv32",          "",               BFD_ENDIAN_BIG},
   {"s390:64-bit",      "zarch",          BFD_ENDIAN_BIG},
};

int get_relocs(bfd *abfd, PyObject **py_symbol_list)
{
   int x;

   int storage_relocs;

   asymbol **symbol_table = NULL;
   arelent **reloc_table = NULL;

   int num_syms_reloc;

   // Return value list
   if (!(*py_symbol_list = PyList_New(0)))
      return -1;

   // Get maximum storage size
   storage_relocs = bfd_get_dynamic_reloc_upper_bound(abfd);

   if(storage_relocs <= 0)
   {
      // No relocs to be had
      return -1;
   }

   symbol_table = (asymbol **) calloc(1, bfd_get_dynamic_symtab_upper_bound(abfd));
   bfd_canonicalize_dynamic_symtab(abfd, symbol_table);

   reloc_table = (arelent **) calloc (1, bfd_get_dynamic_reloc_upper_bound(abfd));
   num_syms_reloc = bfd_canonicalize_dynamic_reloc(abfd, reloc_table, symbol_table);

   // Make sure we've got some relocs. Otherwise return.
   if(num_syms_reloc < 0)
   {
      // Release unused symbol table and return.
      if(symbol_table)
         free(symbol_table);

      return -1;
   }

   DEBUG("RELOCS %d\n", num_syms_reloc);

   for(x = 0; x < num_syms_reloc; x++) 
   {
      arelent *q = reloc_table[x];

      DEBUG("RELOC. %d, %s @ 0x%x\n", x, (*(q->sym_ptr_ptr))->name, q->address);

      PyList_Append(*py_symbol_list,
         Py_BuildValue(
            "(IskI)",
            (*(q->sym_ptr_ptr))->section->index,
            (*(q->sym_ptr_ptr))->name,
            q->address,
            (*(q->sym_ptr_ptr))->flags
         )
      );
   }

   // Release symbol table
   if(symbol_table)
      free(symbol_table);

   // Release reloc table
   if(reloc_table)
      free(reloc_table);

   return num_syms_reloc;
}

static PyObject *pybfd_get_relocs(PyObject *self, PyObject *args)
{
   bfd *abfd;
   PyObject* py_symbol_list = NULL;

   int symbols_count;

   if (PyArg_ParseTuple(args, "n", &abfd))
   {
      if (!abfd)
      {
         // An error ocurred receviing the bfd struct.
         PyErr_SetNone(PyExc_IOError);
      }
      else
      {
         symbols_count = get_relocs(abfd, &py_symbol_list);

         if(symbols_count >= 0)
         {
            // Got symbols
            return Py_BuildValue("O", py_symbol_list);
         }

         PyErr_SetString(PyExc_TypeError, "Unable to get symbols.");
      }
   }
   else
   {
      PyErr_SetString(PyExc_TypeError, "Invalid parameter(s)");
   }

   return NULL;
}

int get_static_symbols(bfd *abfd, PyObject **py_symbol_list)
{
   int x;

   int storage_static;

   asymbol *symbol;
   asymbol **symbol_table;
   asection *section;

   int num_syms_static;

   // Return value list
   if (!(*py_symbol_list = PyList_New(0)))
      return -1;

   // Get maximum storage size for static and dynamic syms
   storage_static = bfd_get_symtab_upper_bound(abfd);

   if(storage_static <= 0)
   {
      // No symbols to be had
      return -1;
   }

   symbol_table = (asymbol **)calloc(1, storage_static);

   num_syms_static = bfd_canonicalize_symtab(abfd, symbol_table);

   // Make sure we've got some symbols. Otherwise return.
   if(num_syms_static < 0)
   {
      // Release unused symbol table and return.
      if(symbol_table)
         free(symbol_table);

      return -1;
   }

   DEBUG("SYMBOLS %d\n", num_syms_static);

   for(x = 0; x < num_syms_static; x++) 
   {
      symbol = symbol_table[x];

      DEBUG("SYM. %d, %s @ 0x%x\n", x, symbol->name, symbol->value);

      // Get section this symbol is in
      section = bfd_get_section(symbol);

      PyList_Append(*py_symbol_list,
         Py_BuildValue(
            "(IskI)",
            symbol->section->index,
            symbol->name,
            section->vma + symbol->value,
            symbol->flags
         )
      );
   }

   // Release symbol table
   if(symbol_table)
      free(symbol_table);

   return num_syms_static;
}

static PyObject *pybfd_get_static_symbols(PyObject *self, PyObject *args)
{
   bfd *abfd;
   PyObject* py_symbol_list = NULL;

   int symbols_count;

   if(PyArg_ParseTuple(args, "n", &abfd))
   {
      if(!abfd)
      {
         // An error ocurred receviing the bfd struct.
         PyErr_SetNone(PyExc_IOError);
      }
      else
      {
         symbols_count = get_static_symbols(abfd, &py_symbol_list);

         if(symbols_count >= 0)
         {
            // Got symbols
            return Py_BuildValue("O", py_symbol_list);
         }

         PyErr_SetString(PyExc_TypeError, "Unable to get static symbols.");
      }
   }
   else
   {
      PyErr_SetString(PyExc_TypeError, "Invalid parameter(s)");
   }

   return NULL;
}

int get_dynamic_symbols(bfd *abfd, PyObject **py_symbol_list)
{
   int x;

   int storage_dynamic;

   asymbol *symbol;
   asymbol **symbol_table;
   asection *section;

   int num_syms_dynamic;

   // Return value list
   if(!(*py_symbol_list = PyList_New(0)))
      return -1;

   // Get maximum storage size for static and dynamic syms
   storage_dynamic = bfd_get_dynamic_symtab_upper_bound (abfd);

   if(storage_dynamic <= 0)
   {
      // No symbols to be had
      return -1;
   }

   symbol_table = (asymbol **)calloc(1, storage_dynamic);

   num_syms_dynamic = bfd_canonicalize_dynamic_symtab(abfd, symbol_table);

   // Make sure we've got some symbols. Otherwise return.
   if(num_syms_dynamic < 0)
   {
      // Release unused symbol table and return.
      if(symbol_table)
         free(symbol_table);

      return -1;
   }

   DEBUG("SYMBOLS %d\n", num_syms_dynamic);

   for(x = 0; x < num_syms_dynamic; x++) 
   {
      symbol = symbol_table[x];

      DEBUG("SYM. %d, %s @ 0x%x\n", x, symbol->name, symbol->value);

      // Get section this symbol is in
      section = bfd_get_section(symbol);

      PyList_Append(*py_symbol_list,
         Py_BuildValue(
            "(IskI)",
            symbol->section->index,
            symbol->name,
            section->vma + symbol->value,
            symbol->flags
         )
      );
   }

   // Release symbol table
   if(symbol_table)
      free(symbol_table);

   return num_syms_dynamic;
}

static PyObject *pybfd_get_dynamic_symbols(PyObject *self, PyObject *args)
{
   bfd *abfd;
   PyObject* py_symbol_list = NULL;

   int symbols_count;

   if(PyArg_ParseTuple(args, "n", &abfd))
   {
      if(!abfd)
      {
         // An error ocurred receviing the bfd struct.
         PyErr_SetNone(PyExc_IOError);
      }
      else
      {
         symbols_count = get_dynamic_symbols(abfd, &py_symbol_list);

         if(symbols_count >= 0)
         {
            // Got symbols
            return Py_BuildValue("O", py_symbol_list);
         }

         PyErr_SetString(PyExc_TypeError, "Unable to get dynamic symbols.");
      }
   }
   else
   {
      PyErr_SetString(PyExc_TypeError, "Invalid parameter(s)");
   }

   return NULL;
}

int get_synthetic_symbols(bfd *abfd, PyObject **py_symbol_list)
{
   int x;
   int synth_count;

   int storage_static;
   int storage_dynamic;

   asymbol *synthsyms;
   asymbol *symbol;
   asymbol **symbol_table;
   asection *section;

   int num_syms_static;
   int num_syms_dynamic;

   // Return value list
   if(!(*py_symbol_list = PyList_New(0)))
      return -1;

   // Get maximum storage size for static and dynamic syms
   storage_static = bfd_get_symtab_upper_bound (abfd);
   storage_dynamic = bfd_get_dynamic_symtab_upper_bound (abfd);

   if(storage_static + storage_dynamic <= 0)
   {
      // No symbols to be had
      return -1;
   }

   symbol_table = (asymbol **)calloc(1, storage_static + storage_dynamic);

   num_syms_static = bfd_canonicalize_symtab(abfd, symbol_table);
   num_syms_dynamic = bfd_canonicalize_dynamic_symtab(abfd, &symbol_table[num_syms_static]);

   // Make sure we've got some symbols. Otherwise return.
   if(num_syms_static + num_syms_dynamic < 0)
   {
      // Release unused symbol table and return.
      if(symbol_table)
         free(symbol_table);

      return -1;
   }

   synth_count = bfd_get_synthetic_symtab(abfd, num_syms_static, symbol_table, num_syms_dynamic, &symbol_table[num_syms_static], &synthsyms);
   
   if(synth_count < 0)
      synth_count = 0;

   DEBUG("SYNTHS %d\n", synth_count);

   for(x = 0; x < synth_count; x++) 
   {
      symbol = synthsyms + x;

      DEBUG("SYM. %d, %s @ 0x%x\n", x, symbol->name, symbol->value);

      // Get section this symbol is in
      section = bfd_get_section(symbol);

      PyList_Append(*py_symbol_list,
         Py_BuildValue(
            "(IskI)",
            symbol->section->index,
            symbol->name,
            section->vma + symbol->value,
            symbol->flags
         )
      );
   }

   // Release symbol table
   if(symbol_table)
      free(symbol_table);

   return synth_count;
}

static PyObject *pybfd_get_synthetic_symbols(PyObject *self, PyObject *args)
{
   bfd *abfd;
   PyObject* py_symbol_list = NULL;

   int symbols_count;

   if (PyArg_ParseTuple(args, "n", &abfd))
   {
      if (!abfd)
      {
         // An error ocurred receviing the bfd struct.
         PyErr_SetNone(PyExc_IOError);
      }
      else
      {
         symbols_count = get_synthetic_symbols(abfd, &py_symbol_list);

         if(symbols_count >= 0)
         {
            // Got symbols
            return Py_BuildValue("O", py_symbol_list);
         }

         PyErr_SetString(PyExc_TypeError, "Unable to get synthetic symbols.");
      }
   }
   else
   {
      PyErr_SetString(PyExc_TypeError, "Invalid parameter(s)");
   }

   return NULL;
}

static PyObject *pybfd_openr(PyObject *self, PyObject *args)
{
   bfd* abfd;

   const char* filename;

   if(PyArg_ParseTuple(args, "s", &filename))
   {
      abfd = bfd_openr(filename, NULL);

      if(!abfd)
      {
         // An error ocurred trying to open the file.
         PyErr_SetString(PyExc_IOError, bfd_errmsg(bfd_get_error()));
         return NULL;
      }

      if(!bfd_check_format(abfd, bfd_object))
      {
         // Unknown file format
         PyErr_SetString(PyExc_IOError, bfd_errmsg(bfd_get_error()));
         return NULL;
      }

      return Py_BuildValue("n", abfd);
   }
   else
   {
      PyErr_SetString(PyExc_TypeError, "Invalid parameter(s)");
   }

    return NULL;
}

static PyObject *pybfd_close(PyObject *self, PyObject *args) 
{
   //
   // Close the specified BFD object.
   //
   bfd* abfd;

   if(PyArg_ParseTuple(args, "n", &abfd))
   {
      // Validate the BFD pointer passes.
      if(!abfd)
      {
         PyErr_SetString(PyExc_TypeError, "Null BFD pointer specified");
      }
      else
      {
         if(bfd_close(abfd) == TRUE)
         {
             Py_RETURN_NONE;
         }

         PyErr_SetString(PyExc_TypeError, "Unable to close BFD.");
      }
   }
   else
   {
      PyErr_SetString(PyExc_TypeError, "Invalid parameter(s)");
   }
   
   return NULL;
}

static PyObject *pybfd_get_sections(PyObject *self, PyObject *args)
{
   bfd *abfd;
   asection *section;

   PyObject *result = NULL;
   PyObject *list = NULL;
   bfd_byte *content;

   if(PyArg_ParseTuple(args, "n", &abfd))
   {
      // Validate the BFD pointer passes.
      if(!abfd)
      {
         PyErr_SetString(PyExc_TypeError, "Null BFD pointer specified");
      }
      else
      {
         // Create a python list with a preexisting number of sections as its
         // size.
         if(!(list = PyList_New(abfd->section_count)))
            return NULL;

         for(section = abfd->sections; section; section = section->next)
         {
            DEBUG("Section %s\n", section->name);

            // Get section contents
            content = (bfd_byte *)calloc(1, section->size);

            if(!bfd_get_section_contents(abfd, section, content, 0, section->size))
            {
               PyErr_SetString(PyExc_TypeError, "Unable to get section contents");
               free(content);
               return result;
            }

            PyList_SetItem(list, section->index, 
            #if PY_MAJOR_VERSION >= 3
               Py_BuildValue("(nisiiiiiiy#)", 
            #else
               Py_BuildValue("(nisiiiiiis#)", 
            #endif
                  section, 
                  section->index, 
                  section->name, 
                  section->size, 
                  section->vma, 
                  section->lma, 
                  section->alignment_power, 
                  section->flags, 
                  section->filepos, 
                  content, 
                  section->size
               )
            );

            free(content);
         }

         result = list;
      }
   }
   else
   {
     PyErr_SetString(PyExc_TypeError, "Invalid parameter(s)");
   }

   return result;
}

static PyObject *pybfd_get_architecture(PyObject *self, PyObject *args)
{
   bfd *abfd;
   int arch;
   int machine;
   int flavour;
   const bfd_arch_info_type *info;

   if(PyArg_ParseTuple(args, "n", &abfd))
   {
      // Validate the BFD pointer passes.
      if(!abfd)
      {
         PyErr_SetString(PyExc_TypeError, "Null BFD pointer specified");
      }
      else
      {
         arch = bfd_get_arch(abfd);
         machine = bfd_get_mach(abfd);
         flavour = bfd_get_flavour(abfd);

         // Lookup info about the architecture
         info = bfd_lookup_arch(arch, machine);

         if(!info)
         {
            PyErr_SetString(PyExc_TypeError, "Unable to get architecture");
            return NULL;
         }

         return Py_BuildValue("(iiiss)", 
            flavour,
            abfd->xvec->byteorder == BFD_ENDIAN_LITTLE,
            info->bits_per_word,
            info->arch_name,
            info->printable_name
         );
      }
   }
   else
   {
      PyErr_SetString(PyExc_TypeError, "Invalid parameter(s)");
   }

   return NULL;
}

int disassemble_sprintf(SFILE *f, const char *format, ...)
{
    size_t n;
    va_list args;
    char* temp_buffer;

    while(1)
    {
        size_t space = f->alloc - f->pos;

        va_start (args, format);
        n = vsnprintf (f->buffer + f->pos, space, format, args);
        va_end (args);

        // Determine if we need more space to hold the current disassembly.
        if (space > n)
            break;

        f->alloc = (f->alloc + n) * 2;

        temp_buffer = (char *) realloc (f->buffer, f->alloc);

        if (!temp_buffer) {
            // When realloc fails it returns NULL and the original buffer
            // remains untouched.
            free(f->buffer);
            f->alloc = f->pos = 0;
            return 0;
        }

        f->buffer = temp_buffer;
    }
    f->pos += n;

    return n;
}

int disassemble_bytes(bfd *abfd, PyObject **py_instr_list, int arch_num, char *data, size_t len, size_t vma)
{
   #define DEFAULT_SKIP_ZEROES 8
   #define DEFAULT_SKIP_ZEROES_AT_END 3

   int x = 0;
   int bytes;
   size_t current_addr;
   struct disassemble_info disasm_info;
   struct bfd_target *xvec;
   const bfd_arch_info_type *inf;

   SFILE sfile;

   // Create a dummy bfd struct without actually creating a new file
   bfd *new_abfd = bfd_create("dummy", abfd);

   // Allocate buffer for disassembled strings
   sfile.pos = 0;
   sfile.alloc = 10 * 1024;
   sfile.buffer = (char *)malloc(sfile.alloc);

   if(!(*py_instr_list = PyList_New(0)))
      return 0;

   init_disassemble_info(&disasm_info, &sfile, (fprintf_ftype) disassemble_sprintf);

   // Initialize the info
   inf = bfd_scan_arch(archs[arch_num].arch_name);

   if(inf == NULL)
   {
      // Can't use supplied machine
      return 0;
   }
   new_abfd->arch_info = inf;

   // Set endianess
   xvec = (struct bfd_target *) malloc(sizeof(struct bfd_target));
   memcpy(xvec, new_abfd->xvec, sizeof(struct bfd_target));
   xvec->byteorder = archs[arch_num].endianess;
   new_abfd->xvec = xvec;

   // Use libopcodes to locate a suitable disassembler
   disassembler_ftype disassemble_fn = disassembler(new_abfd);

   if(!disassemble_fn)
   {
      printf("Can't disassemble for architecture %s\n", bfd_printable_arch_mach(bfd_get_arch(new_abfd), 0));
      return 0;
   }

   // Allow the target to customize the info structure.
   disassemble_init_for_target(&disasm_info);
   disasm_info.flavour = bfd_get_flavour(new_abfd);
   disasm_info.arch = bfd_get_arch(new_abfd);
   disasm_info.mach = bfd_get_mach(new_abfd);
   disasm_info.octets_per_byte = bfd_octets_per_byte(new_abfd);
   disasm_info.skip_zeroes = DEFAULT_SKIP_ZEROES;
   disasm_info.skip_zeroes_at_end = DEFAULT_SKIP_ZEROES_AT_END;
   disasm_info.disassembler_needs_relocs = FALSE;
   disasm_info.bytes_per_line = 0;
   disasm_info.bytes_per_chunk = 0;
   disasm_info.flags = DISASSEMBLE_DATA;

   disasm_info.disassembler_options = archs[arch_num].disasm_options;
   disasm_info.buffer = (bfd_byte *)data;
   disasm_info.buffer_vma = vma;
   disasm_info.buffer_length = len;

   disasm_info.display_endian = disasm_info.endian = archs[arch_num].endianess;

    disassemble_init_for_target(&disasm_info);

   current_addr = vma;

   while(current_addr < vma + len)
   {
      memset(sfile.buffer, 0, sfile.alloc);
      sfile.pos = 0;
      bytes = disassemble_fn((bfd_vma)current_addr, &disasm_info);

      PyList_Append(*py_instr_list,
         Py_BuildValue("(iis#)",
            current_addr,
            bytes,
            sfile.buffer,
            strlen(sfile.buffer)

         )
      );

      current_addr += bytes;
      x++;
   }

   // Cleanup
   free(sfile.buffer);
   free(xvec);

   return 1;
}

static PyObject *pybfd_disassemble_bytes(PyObject *self, PyObject *args)
{
   bfd *abfd;

   PyObject *result = NULL;
   PyObject *py_instr_list = NULL;
   char *data;
   int arch_num;
   int data_len;
   size_t vma;

   if(PyArg_ParseTuple(args, "nis#i", &abfd, &arch_num, &data, &data_len, &vma))
   {
      // Validate the BFD pointer passes.
      if(!abfd)
      {
         PyErr_SetString(PyExc_TypeError, "Null BFD pointer specified");
         return NULL;
      }

      disassemble_bytes(abfd, &py_instr_list, arch_num, data, data_len, vma);
      
      result = py_instr_list;
   }
   else
   {
     PyErr_SetString(PyExc_TypeError, "Invalid parameter(s)");
   }

   return result;
}

//
// Define methods
//
static struct PyMethodDef BfdMethods[] = { 
#define declmethod(func,h) { #func , pybfd_##func , METH_VARARGS , h }
   declmethod(openr, "Open file for reading"),
   declmethod(close, "Close the descriptor"),
   declmethod(get_synthetic_symbols, "Get synthetic symbols"),
   declmethod(get_static_symbols, "Get static symbols"),
   declmethod(get_dynamic_symbols, "Get dynamic symbols"),
   declmethod(get_relocs, "Get relocations"),
   declmethod(get_sections, "Get sections"),
   declmethod(get_architecture, "Get architecture information"),
   declmethod(disassemble_bytes, "Disassemble chunk of bytes"),
   {NULL},
#undef declmethod
};

#if PY_MAJOR_VERSION >= 3
   static struct PyModuleDef moduledef = {
      PyModuleDef_HEAD_INIT,
      "bfdpie",
      NULL,
      -1,
      BfdMethods,
      NULL,
      NULL,
      NULL,
      NULL
   };
#endif

#if PY_MAJOR_VERSION >= 3
PyObject *PyInit__bfdpie(void)
#else
PyMODINIT_FUNC init_bfdpie(void)
#endif
{
   #if PY_MAJOR_VERSION >= 3
      PyObject *module = PyModule_Create(&moduledef);
   #else
      (void) Py_InitModule("_bfdpie", BfdMethods);
   #endif

   // Initialize BFD
   bfd_init();

   #if PY_MAJOR_VERSION >= 3
      return module;
   #endif
}

