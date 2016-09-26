#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import random
import copy

from utils import *


class WichteliSolver:

    def __init__(self, users, exclusions):
        self.log = logging.getLogger(__name__)
        self.log.debug("[Wichteli] Initializing WichteliSolver")

        self.users = users
        self.exclusions = exclusions

        self.solutionFound = False

    def getWichteli(self, wichteli):
        aValues = random.choice(wichteli)
        aIndex = wichteli.index(aValues)
        wichteli.pop(aIndex)
        return (wichteli, aValues)

    def getKey(self, myDict):
        for key in myDict.keys():
            return key

    def run(self):
        self.solutionFound = False
        calcCountTotal = 0

        while not self.solutionFound:
            self.log.info("[Wichteli] Starting to solve")
            result = []
            pairsFound = False
            wichteliS = copy.copy(self.users)
            wichteliR = copy.copy(self.users)

            maxRuns = 10 * len(self.users) ^ 2

            calcCount = 0
            while not pairsFound:
                calcCount += 1

                if calcCount > maxRuns:
                    self.log.warning("[Wichteli] Unresolvable!")
                    calcCountTotal += calcCount
                    return False

                wichteliST = copy.copy(wichteliS)
                wichteliRT = copy.copy(wichteliR)
                (wichteliST, A) = self.getWichteli(wichteliST)
                (wichteliRT, B) = self.getWichteli(wichteliRT)

                self.log.debug("[Wichteli] A: %s; B: %s" % (A.name, B.name))

                if A != B:
                    badPair = False

                    for exclusion in self.exclusions:
                        if exclusion.check(A.id, B.id):
                            badPair = True
                            break

                    if not badPair:
                        wichteliS = wichteliST
                        wichteliR = wichteliRT
                        self.log.info("[Wichteli] Result found: %s - %s" %
                                      (A.name, B.name))
                        result.append((A, B))
                        calcCountTotal += calcCount
                        calcCount = 0

                if len(wichteliR) == 0:
                    pairsFound = True
                    self.solutionFound = True

        self.log.info("[Wichteli] Needed calculations: %s" % (calcCountTotal))
        return result
