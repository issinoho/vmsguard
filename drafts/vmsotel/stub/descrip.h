/* Linux stub of the VMS string descriptor: layout as documented. */
#ifndef STUB_DESCRIP_H
#define STUB_DESCRIP_H
struct dsc$descriptor_s {
    unsigned short dsc$w_length;
    unsigned char dsc$b_dtype;
    unsigned char dsc$b_class;
    char *dsc$a_pointer;
};
#define DSC$K_DTYPE_T 14
#define DSC$K_CLASS_S 1
#endif
