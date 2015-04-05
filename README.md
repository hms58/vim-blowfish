# vim-blowfish
An attempt to extract from Vim the VimCrypt02 and VimCrypt03 algorithms.

The goal is to implement it in Perl, Python and JavaScript and have extensive tests with original Vim 7.4 files. 

The files below are identical to those used in Vim 7.4.691:

- blowfish.c
- sha256.c

Currently this implementation built but does not work. The blowfish self-test does not pass. I don't know why.

![](https://travis-ci.org/nowox/vim-blowfish.svg)
