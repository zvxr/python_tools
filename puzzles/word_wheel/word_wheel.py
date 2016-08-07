
"""Word Wheels are a type of word building puzzle. You are supplied a group of
letters where one must be used, and every other one may only be used once. The
object is to generate as many words as possible in a given period of time.
Visually word wheels will usually be displayed as a circle, where the center
letter is the letter that must be used in all words. Example:
   _____
 /\     /\
/  \ r /  \
| b (a) e |
\  / c \  /
 \/_____\/

Valid Words: car, care, race
Invalid Words: bee (must contain A and not enough E's), bark (no K)

"""

import atexit
import curses

from collections import defaultdict


class Wheel(object):
    def __init__(self, center_choice, choices):
        self.center_choice = center_choice.upper()
        self.choices = list(ch.upper() for ch in choices) + [self.center_choice]
        self.solutions = set()

    def get_solution_count(self):
        """Return a defaultdict that groups length of solutions."""
        solution_count = defaultdict(list)
        for size, sol in ((len(sol), sol) for sol in self.solutions):
            solution_count[size].append(sol)

        return solution_count

    def matches(self, string):
        """Return Boolean indicating if string is valid."""
        if self.center_choice not in string:
            return False

        choices_left = list(self.choices)
        for ch in string:
            if ch not in choices_left:
                return False
            choices_left.pop(choices_left.index(ch))
        return True


class Screen(object):
    def __init__(self):
        self.stdscr = curses.initscr()
        #curses.noecho()
        atexit.register(self.cleanup)

    def __del__(self):
        self.cleanup()

    def cleanup(self):
        self.stdscr.keypad(0)
        curses.echo();
        curses.nocbreak()
        curses.endwin()
