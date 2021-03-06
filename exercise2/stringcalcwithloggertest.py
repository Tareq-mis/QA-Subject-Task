from unittest import TestCase
import logging
#from unittest.mock import Mock
from stringcalcwithlogger import StringCalculator, NegativeInputException


# create and configuer logger
LOG_FORMAT = "%(levelname)s - %(message)s"
logging.basicConfig(filename="F:\\ME 2nd semester\\Quality Assurance\\QA-Task\\exercise2\\Strcalc.log",
                    level=logging.DEBUG, format=LOG_FORMAT)
logger = logging.getLogger()

class StringCalculatorTest(TestCase):

    def _init_calculator(self):
        return StringCalculator()

    def setUp(self):
        self.target = self._init_calculator()

    def test_empty_string_gives_0(self):
        self.assertEqual(self.target.add(''), 0)

    def test_multiple_empty_string_gives_0(self):
        self.assertEqual(self.target.add(' '), 0)

    def test_single_number_gives_itself(self):
        self.assertEqual(self.target.add('1'), 1)
        self.assertEqual(self.target.add('123'), 123)

    def test_two_numbers_gives_sum(self):
        self.assertEqual(self.target.add('1,2'), 3)

    def test_new_line_allowed_as_seperator(self):
        self.assertEqual(self.target.add('1\n2'), 3)

    def test_new_line_with_empty_line_disallowed(self):
        self.assertEqual(self.target.add('1,\n'), '')

    def test_different_delimiters_in_input(self):
        self.assertEqual(self.target.add('1\n2,3'), 6)
        self.assertEqual(self.target.add('1,2\n3'), 6)

    def test_custom_delimiter_specification(self):
        self.assertEqual(self.target.add('//;\n1;2;6'), 9)

    def test_negative_number_raises_exception(self):
        with self.assertRaises(NegativeInputException):
            self.target.add('-1\n2')
            self.target.add('-1\n2,3')
            self.target.add('-1,2,3')
            self.target.add('1,2,-3')

    def test_negative_number_exception_has_all_negative_inputs(self):
        try:
            self.target.add('-1,-2,3,-4')
        except NegativeInputException as nie:
            self.assertIn(', '.join(map(str, [-1, -2, -4])), str(nie))

    def test_numbers_greater_than_1000_are_ignored(self):
        self.assertEqual(self.target.add('1,2,1000'), 1003)
        self.assertEqual(self.target.add('1,2,1001'), 3)
        self.assertEqual(self.target.add('1001'), 0)

    def test_delimiter_can_be_of_any_length(self):
        self.assertEqual(self.target.add('//;;;\n1;;;2;;;3'), 6)
        self.assertEqual(self.target.add('//**\n1**2**3'), 6)
        self.assertEqual(self.target.add('//----\n1----2----3'), 6)
        self.assertEqual(self.target.add('//----\n1----2\n3'), 6)

    def test_delimiter_can_be_of_any_length_with_square_brackets(self):
        self.assertEqual(self.target.add('//[;;;]\n1;;;2;;;3'), 6)
        self.assertEqual(self.target.add('//[**]\n1**2**3'), 6)
        self.assertEqual(self.target.add('//[----]\n1----2----3'), 6)
        self.assertEqual(self.target.add('//[----]\n1----2\n3'), 6)

    def test_logtheSum(self):
        with self.assertLogs( level='INFO') as cm:
            logger.info("add({0},The sum {1})".format('1,2' ,'3'))
        self.assertEqual(cm.output, ['INFO:root:add(1,2,The sum 3)'])

    def test_logtheNegnumException(self):
        with self.assertLogs( level='CRITICAL') as cm:
            logger.critical("add({0},Exception {1})".format('-1, -2, -4', 'Negative inputs: -1, -2, -4)'))
        self.assertEqual(cm.output, ['CRITICAL:root:add(-1, -2, -4,Exception Negative inputs: -1, -2, -4))'])