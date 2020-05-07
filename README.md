# Asymmetric flow with window

## Introduction
![topology](./topo.png)

Basic idea is that aymmetric flow detection reset itself after no traffic for a window of time. 

A register called window saves timestamp of the last packet for each flow. 

when a new packet arrives, if it's been longer than X seconds since the last packet on the same route, this trigger a reset in the asymmetric flow detection progress, and traffic resume as usual.

WINDOW  : 15 seconds



