#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import random
import copy

from utils import *


class WichteliSolver:

    def __init__(self, users, notwants):
        self.log = logging.getLogger(__name__)
        self.log.debug("[Wichteli] Initializing WichteliSolver")

        self.users = users
        self.notwants = notwants

        self.solutionFound = False

    def getWichteli(self, wichteli):
        aValues = random.choice(wichteli)
        aIndex = wichteli.index(aValues)
        wichteli.pop(aIndex)
        return (wichteli, aValues)

    def getKey(self, myDict):
        for key in myDict.keys():
            return key

    def run(self, config):
        self.solutionFound = False
        calcCountTotal = 0

        while not self.solutionFound:
            self.log.debug("[Wichteli] Starting to solve")
            result = []
            pairsFound = False
            wichteliS = copy.copy(config['wichteli'])
            wichteliR = copy.copy(config['wichteli'])

            maxRuns = 10 * len(config['wichteli']) ^ 2

            calcCount = 0
            while not pairsFound:
                calcCount += 1

                if calcCount > maxRuns:
                    self.log.debug("[Wichteli] Unresolvable!")
                    calcCountTotal += calcCount
                    break

                wichteliST = copy.copy(wichteliS)
                wichteliRT = copy.copy(wichteliR)
                (wichteliST, A) = self.getWichteli(wichteliST)
                (wichteliRT, B) = self.getWichteli(wichteliRT)

                if A != B:
                    nameA = self.getKey(A)
                    nameB = self.getKey(B)
                    badPair = False

                    try:
                        for entry in config['notwant'][nameA]:
                            if entry == nameB:
                                badPair = True
                    except Exception:
                        pass
                    try:
                        for entry in config['notwant'][nameB]:
                            if entry == nameA:
                                badPair = True
                    except Exception:
                        pass

                    if not badPair:
                        wichteliS = wichteliST
                        wichteliR = wichteliRT
                        self.log.debug("[Wichteli] Result found: %s - %s" % (nameA, nameB))
                        result.append((nameA, nameB))
                        calcCountTotal += calcCount
                        calcCount = 0

                if len(wichteliR) == 0:
                    pairsFound = True
                    self.solutionFound = True

        self.log.info("[Wichteli] Needed calculations: %s" % (calcCountTotal))
        return result
