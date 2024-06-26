# https://fsymbols.com/generators/smallcaps/

from lib.color import Color


class Logo:
    def __init__(self, script):
        self.script = script

        self.c = Color()

    def print(self):
        print('\n' + self.c.RED + u'''☎️  STUNCHECK''' + self.c.WHITE +
              ''' BY ''' + self.c.GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + self.c.YELLOW)

        print(self.get_logo() + self.c.WHITE)

        print('' + self.c.GREEN +
              '''💾 https://github.com/Pepelux/stuncheck''' + self.c.WHITE)
        print('' + self.c.BLUE +
              '''🐦 https://twitter.com/pepeluxx\n''' + self.c.WHITE)

    def get_logo(self):
        if self.script == 'stunscan':
            return '''
██████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█
█▄▄▄▄─███─████─██─███─█▄▀─██▄▄▄▄─█─███▀██─▀─███─█▄▀─██
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀
            '''

        if self.script == 'stunlogin':
            return '''
███████████████████████████████████████████▀█████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄███─▄▄─█─▄▄▄▄█▄─▄█▄─▀█▄─▄█
█▄▄▄▄─███─████─██─███─█▄▀─███─██▀█─██─█─██▄─██─███─█▄▀─██
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▄▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▄▄▀
            '''

        if self.script == 'stuninfo':
            return '''
███████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄█▄─▀█▄─▄█▄─▄▄─█─▄▄─█
█▄▄▄▄─███─████─██─███─█▄▀─███─███─█▄▀─███─▄███─██─█
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▀▀▀▄▄▄▄▀
            '''

        if self.script == 'stuntransports':
            return '''
█████████████████████████████████████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█─▄─▄─█▄─▄▄▀██▀▄─██▄─▀█▄─▄█─▄▄▄▄█▄─▄▄─█─▄▄─█▄─▄▄▀█─▄─▄─█─▄▄▄▄█
█▄▄▄▄─███─████─██─███─█▄▀─████─████─▄─▄██─▀─███─█▄▀─██▄▄▄▄─██─▄▄▄█─██─██─▄─▄███─███▄▄▄▄─█
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▀▄▄▄▀▀▄▄▀▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▀▀▀▄▄▄▄▀▄▄▀▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀
            '''

        if self.script == 'stunportscan':
            return '''
█████████████████████████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄▄─█─▄▄─█▄─▄▄▀█─▄─▄─█─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█
█▄▄▄▄─███─████─██─███─█▄▀─███─▄▄▄█─██─██─▄─▄███─███▄▄▄▄─█─███▀██─▀─███─█▄▀─██
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▀▀▀▄▄▄▄▀▄▄▀▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀
            '''

        if self.script == 'stunsocks':
            return '''

█████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█─▄▄▄▄█─▄▄─█─▄▄▄─█▄─█─▄█─▄▄▄▄█
█▄▄▄▄─███─████─██─███─█▄▀─██▄▄▄▄─█─██─█─███▀██─▄▀██▄▄▄▄─█
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀
            '''

        if self.script == 'stunipscan':
            return '''

████████████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄█▄─▄▄─█─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█
█▄▄▄▄─███─████─██─███─█▄▀─███─███─▄▄▄█▄▄▄▄─█─███▀██─▀─███─█▄▀─██
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▀▄▄▄▀▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀
            '''

        if self.script == 'stunsniff':
            return '''

██████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█─▄▄▄▄█▄─▀█▄─▄█▄─▄█▄─▄▄─█▄─▄▄─█
█▄▄▄▄─███─████─██─███─█▄▀─██▄▄▄▄─██─█▄▀─███─███─▄████─▄███
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▀▄▄▄▀▀▀▄▄▄▀▀▀
            '''

        if self.script == 'stunpcapdump':
            return '''

███████████████████████████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄▄─█─▄▄▄─██▀▄─██▄─▄▄─█▄─▄▄▀█▄─██─▄█▄─▀█▀─▄█▄─▄▄─█
█▄▄▄▄─███─████─██─███─█▄▀─███─▄▄▄█─███▀██─▀─███─▄▄▄██─██─██─██─███─█▄█─███─▄▄▄█
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▀▀▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▀▄▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▄▄▄▀▄▄▄▀▀▀
            '''
