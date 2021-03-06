import re


class StringCalculator():
    def __init__(self):
        self.delimiter_re = re.compile(r'\[(.*)\]')
        self.separator = ','

    @staticmethod
    def _parse_single_number(inp):
        try:
            return int(inp)
        except ValueError:
            return None

    def _split_numbers(self, inp):
        lines = inp.split('\n')
        if [l for l in lines if l.strip() == '']:
            return None
        return self.separator.join(lines).strip().split(self.separator)

    def _parse_multiple_numbers(self, inp):
        try:
            return list(map(int, self._split_numbers(inp)))
        except (ValueError, TypeError):
            return None

    def _parse_custom_delimiter(self, inp):
        delimiter, inp = inp.split('\n', 1)
        self.separator = delimiter.lstrip('/')
        re_match = self.delimiter_re.match(self.separator)
        if re_match:
            self.separator = re_match.group(1)
        return inp

    def add(self, inp):
        if not inp.strip():
            return 0

        if inp.startswith('//'):
            inp = self._parse_custom_delimiter(inp)

        numbers = []
        single_num = self._parse_single_number(inp)
        if single_num:
            numbers.append(single_num)
        else:
            numbers = self._parse_multiple_numbers(inp)

        if not numbers:
            return ''

        neg_numbers = [n for n in numbers if n < 0]
        if neg_numbers:
            raise NegativeInputException(neg_numbers)

        return sum([n for n in numbers if n <= 1000])


class NegativeInputException(Exception):
    def __init__(self, inputs):
        self._inputs = inputs

    def __str__(self):
        return "Negative input{0}: {1}".format('s' if len(self._inputs) else '',
                                               ', '.join(map(str, self._inputs)))


