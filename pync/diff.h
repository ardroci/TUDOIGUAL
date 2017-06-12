#ifndef DIFF_H
#define DIFF_H

void backup(int dirfd, const char *file);
char *pdiff(int dirfd, const char *filename_a, int *size);
void adiff(int dirfd, char *diff);

#endif /* !DIFF_H */
