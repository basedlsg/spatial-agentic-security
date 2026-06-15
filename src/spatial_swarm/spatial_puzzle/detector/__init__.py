"""Detector subpackage: 3D geometry as a tamper-detector vs a non-geometric tripwire.

The random committed secret is the lock (prior findings: 3D is a worse lock than a
random secret). This package tests the parallel question for the *detector* role:
does a geometric detector catch any attack a plain commitment tripwire misses, at
equal-or-lower false-positive rate, and without leaking more? Mirrors the keystone
method (`experiments/fair_baselines.py`) one level up.
"""
