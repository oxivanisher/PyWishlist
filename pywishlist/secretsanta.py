#!/usr/bin/env python
# -*- coding: utf-8 -*-

import copy
import random
from operator import itemgetter

from pywishlist.utils import *


class SecretSantaSolver:

    def __init__(self, users, exclusions, history):
        self.log = logging.getLogger(__name__)
        self.log.debug("[SecretSanta] Initializing SecretSantaSolver")

        self.users = users
        self.exclusions = exclusions
        self.history = history
        self.loops = 0

        self.solutionFound = False

    def getSecretSanta(self, SecretSanta):
        aValues = random.choice(SecretSanta)
        aIndex = SecretSanta.index(aValues)
        SecretSanta.pop(aIndex)
        return (SecretSanta, aValues)

    def getKey(self, myDict):
        for key in myDict.keys():
            return key

    def run2(self):
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
                    self.loops += calcCount
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
                        self.log.debug("[SecretSanta] Result found: %s - %s" %
                                       (A.name, B.name))
                        result.append((A, B))
                        self.loops += calcCount
                        calcCount = 0

                if len(SecretSantaR) == 0:
                    pairsFound = True
                    self.solutionFound = True

        self.log.info("[SecretSanta] Needed calculations: %s" % (self.loops))
        return result

    def run(self):
        result = []
        for x in range(1,500):
            result = self.run3()
            if len(result) != 10:
                self.log.warning("Wrong solution found, number of entries")
            for y in range(1,10):
                if y not in [y[0] for y in result]:
                    self.log.warning("Wrong solution found, donator entry missing")
                if y not in [y[1] for y in result]:
                    self.log.warning("Wrong solution found, receiver entry missing")

        return result

    def run3(self):
        user_ids = [user.id for user in self.users]
        timestamps = sorted(list(set([hist.date for hist in self.history])), reverse=True)
        max_score = len(timestamps) * 10

        solution = []
        while len(solution) != len(user_ids):
            pairs = dict([((x, y), random.randint(0, 9)) for x in user_ids for y in user_ids if x != y])

            for exclusion_entry in self.exclusions:
                key1 = (exclusion_entry.userIdA, exclusion_entry.userIdB)
                key2 = (exclusion_entry.userIdB, exclusion_entry.userIdA)
                pairs[key1] = max_score
                pairs[key2] = max_score

            for history_entry in self.history:
                # todo limit by half of total users
                current_score = min(timestamps.index(history_entry.date), len(user_ids) / 2) * 10 + random.randint(0, 9)
                key = (history_entry.donatorId, history_entry.recieverId)
                if current_score > pairs[key]:
                    pairs[key] = current_score


            sorted_pairs = sorted(pairs.items(), key=itemgetter(1), reverse=True)
            solution_pairs = sorted(pairs.items(), key=itemgetter(1), reverse=True)

            solution = self.calculate_solution(solution_pairs, sorted_pairs)
        return solution

    def calculate_solution(self, solution_pairs, sorted_pairs):
        for pair in sorted_pairs:
            if pair in solution_pairs:
                other_receiver_exists = sum(1 for x in solution_pairs if x[0][0] == pair[0][0]) > 1
                other_donator_exists = sum(1 for x in solution_pairs if x[0][1] == pair[0][1]) > 1
                if other_receiver_exists and other_donator_exists:
                    solution_pairs.remove(pair)
                else:
                    remove_pairs = [x for x in solution_pairs if (x[0][0] == pair[0][0] or x[0][1] == pair[0][1]) and x != pair]
                    for rm in remove_pairs:
                        solution_pairs.remove(rm)

        return [solution_pair[0] for solution_pair in solution_pairs]
