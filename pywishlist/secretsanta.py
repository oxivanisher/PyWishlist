#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import random
import copy

from utils import *


class SecretSantaSolver:

    def __init__(self, users, exclusions):
        self.log = logging.getLogger(__name__)
        self.log.debug("[SecretSanta] Initializing SecretSantaSolver")

        self.users = users
        self.exclusions = exclusions

        self.solutionFound = False

    def getSecretSanta(self, SecretSanta):
        aValues = random.choice(SecretSanta)
        aIndex = SecretSanta.index(aValues)
        SecretSanta.pop(aIndex)
        return (SecretSanta, aValues)

    def getKey(self, myDict):
        for key in myDict.keys():
            return key

    def run(self):
        self.solutionFound = False
        calcCountTotal = 0

        while not self.solutionFound:
            self.log.info("[SecretSanta] Starting to solve")
            result = []
            pairsFound = False
            SecretSantaS = copy.copy(self.users)
            SecretSantaR = copy.copy(self.users)

            maxRuns = 10 * len(self.users) ^ 2

            calcCount = 0
            while not pairsFound:
                calcCount += 1

                if calcCount > maxRuns:
                    self.log.warning("[SecretSanta] Unresolvable!")
                    calcCountTotal += calcCount
                    return False

                SecretSantaST = copy.copy(SecretSantaS)
                SecretSantaRT = copy.copy(SecretSantaR)
                (SecretSantaST, A) = self.getSecretSanta(SecretSantaST)
                (SecretSantaRT, B) = self.getSecretSanta(SecretSantaRT)

                self.log.debug("[SecretSanta] A: %s; B: %s" % (A.name, B.name))

                if A != B:
                    badPair = False

                    for exclusion in self.exclusions:
                        if exclusion.check(A.id, B.id):
                            badPair = True
                            break

                    if not badPair:
                        SecretSantaS = SecretSantaST
                        SecretSantaR = SecretSantaRT
                        self.log.info("[SecretSanta] Result found: %s - %s" %
                                      (A.name, B.name))
                        result.append((A, B))
                        calcCountTotal += calcCount
                        calcCount = 0

                if len(SecretSantaR) == 0:
                    pairsFound = True
                    self.solutionFound = True

        self.log.info("[SecretSanta] Needed calculations: %s" % (calcCountTotal))
        return result
