Wannacry unpacking Miasm-based script
=====================================

This script unpacks the Wannacry dll using Miasm. This still needs some cleanup
and proper explication on how this works internally.

Usage
-----

You first need to install Miasm (https://github.com/cea-sec/miasm/) and llvmlite (``pip install llvmlite``).

Gather the address of the ``WinMain`` function in wcry.exe.infected (0x401FE7), and run:

.. code::

  $ python ./unpack.py -jllvm -a 0x401FE7 -y wcry.exe.infected
