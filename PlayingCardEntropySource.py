"""
Playing card entropy source.

Convert 31 playing cards to or from a hexadecimal number.

The number is represented in hexadecimal, for ease of conversion into 
formats such as a bitcoin private key.  It is not recommended to 
generate a private key using a machine connected to the internet, or 
that may later be connected to the internet.  This program cannot 
protect a private key from theft.

The 31 cards should be chosen without replacement, so no two of them 
are the same.  For example, the ace of spades can appear at most once 
in the list of 31 cards.  The maximum number which can be represented 
with 31 cards is slightly higher than the maximum number which can be 
represented using 160 bits.

31 cards gives 52!/(52-31)! which is approximately 1.58E+48
160 bits gives 2**160 which is approximately 1.46E+48

This algorithm does not restrict the range to 160 bits as it is 
intended for use with bitcoin private keys, which allow 256 bits.  
Approximately 7.4% of lists of 31 cards will give a number > 2**160 
but these will still be valid numbers to use as bitcoin private keys.

Rather than a base 52 system, this algorithm uses a drifting base due 
to the cards being chosen without replacement.  Note that simply 
treating each card as a number from 0 to 51 would exclude the 
possibility of choosing any number (private key) which is represented 
by more than one of the same card.  The representation used therefore 
treats the first card as a number from 0 to 51, the second as a number 
from 0 to 50, then 0 to 49 and so on.  This ensures that every number 
from 0 to (52!/(52-31)! - 1) is represented by exactly one list of 31 
cards with no repetition of the same card.

For comparison, in decimal there is a units column, a tens column, a 
hundreds column, and so on.  In this card representation, the first 
card is like the units column.  The second card represents multiples 
of 52.  The third card represents multiples of (52*51), then the 
fourth represents multiples of (52*51*50) and so on.

The numerical value of a given card will change depending on the cards 
that came before it, so that there are never gaps in the 
representation.  For example, the ace of spades initially represents 
zero.  If the ace of spades is used as the first card, then all the 
other cards are shifted down in value, so that the two of spades now 
represents zero instead of one, and the king of clubs now represents 
50 instead of 51.

The algorithm provided here is not unique.  If you simply want to 
generate a private key and will not be converting it back to a list of 
cards, then any valid algorithm will do.  The choice of algorithm is 
only important if you store the key in the form of a list of cards.  
The important thing to remember is that a list of 31 cards alone does 
not define a private key.  It is also necessary to know which 
algorithm to use (including which card ordering).  However, this fact
should never be relied on for secure storage of private keys.

This is only one example of such an algorithm that provides a 
bijection from the possible lists of 31 cards without repetition to 
the numbers from 0 to 
1,578,717,708,901,572,902,259,045,031,706,959,124,889,599,999,999.

Another example would be a "Bigendian" approach to a drifting base, 
using the first card (representing a number from 0 to 51) as the most 
significant card, instead of the least significant card as it is in 
this algorithm.  Although it is a very similar approach it actually 
leads to a completely different list of column multiples.  However, 
the result is still a bijection covering the required range of 
numbers.  Obviously this maps each list of 31 cards to a completely 
different number than the algorithm implemented here does.  This is 
the reason I mention it.  If you wish to convert back and forth 
between lists of cards and private keys, then it is essential to use 
the same algorithm throughout.  Either of these will work if 
used consistently, but the Bigendian approach will give back a 
completely different list of cards, if it was not the algorithm used 
initially.

Similarly the ordering of the cards affects which private key a list 
of 31 cards will generate.  The ordering used here is the ordering 
used in Unicode, as introduced in Unicode 6.0 (excluding the knights, 
which are not part of a standard 52 card pack, and also excluding 
jokers).

This algorithm can return the original list of 31 cards given any 
hexadecimal private key generated using this algorithm.  However, the 
space of valid bitcoin private keys is far larger than the space of 
possible lists of 31 cards.  This algorithm therefore cannot convert 
an arbitrary bitcoin private key into a list of 31 cards.

If you wish to write an algorithm that can, please bear in mind that 
this would involve finding a preimage to the RIPEMD-160 hash.  The 
global community would probably appreciate a few months warning before 
you make such an algorithm public.

I have implemented this algorithm in Python, mainly because I find it 
enjoyable and relaxing to write in.  The algorithm can of course be 
converted to the language of your choice, with the following entropy 
warning.

Python calculates integers to arbitrary precision, so that 2**160 is 
1,461,501,637,330,902,918,203,684,832,716,283,019,655,932,542,976.  
It is important that whatever language you choose can also do this 
(natively or by writing/finding code that will).  Some languages will 
represent 2**160 as 1.4615016373309E+48.  For working with large 
integers this would be unsuitable.  In particular, in cases requiring 
entropy this would lead to a significant loss of entropy with each 
calculation.  For the algorithm overall, the loss of entropy would be 
magnified further.

This does not limit the range of languages in which the algorithm 
could be written.  It simply means that some languages will require 
more work to ensure there is no loss of precision.  The precision 
problem is important for two reasons.
1. Using an imprecise algorithm means that reversing the process may 
not give back what you started with (risk of losing your private key).
2. Using very low entropy permits a successful brute force attack 
(risk of someone else finding your private key).

"""

from math import factorial

class Error(Exception):
    """Base class for exceptions in this module."""
    pass
    
class TooFewCardsError(Error):
    """Exception for input with fewer than 62 nonwhitespace characters."""
    pass
    
class TooManyCardsError(Error):
    """Exception for input with more than 62 nonwhitespace characters."""
    pass
    
class UnrecognisedCardRankError(Error):
    """Exception for input containing an invalid rank character."""
    pass
    
class UnrecognisedCardSuitError(Error):
    """Exception for input containing an invalid suit character."""
    pass

class DuplicatedCardsError(Error):
    """Exception for input containing the same card more than once."""
    pass
    
class HexValueTooLargeError(Error):
    """Exception for input representing a number too large for 31 cards."""
    pass
    
    
FACTORIAL_52 = factorial(52)
UPPER_LIMIT = FACTORIAL_52//factorial(52-31) - 1
CARD_RANKS = "A23456789TJQK"
CARD_SUITS = "SHDC"
ALL_CARDS = [(rank + suit) for suit in CARD_SUITS for rank in CARD_RANKS]

def request_input():
    print(
        "\n"
        "Enter a list of 31 playing cards in the format\n"
        "AS 2H 3D 4C 5S 6H 7D 8C 9S TH JD QC KS ...\n"
        "\n"
        "or a hexadecimal number in the range\n"
        "0 to 114882682E46B11EADE9F57C1E3E0BBD47FFFFFFF (52! / (52-31)! - 1)\n"
        "\n"
        "In either case you may include spaces or not as you wish.\n"
        "Use T rather than 10.  For example TH for ten of hearts.\n"
        "Upper and lower case letters are equivalent.\n"
        "\n"
        )
    return input()
        
def decide_how_to_convert(inputString):
    """Convert the argument from cards to hex or hex to cards.
    
    Decide whether the argument is hexadecimal or a list of cards.
    Ambiguity is possible, as some of the characters used to 
    represent cards are valid hexadecimal characters.  However, a 
    valid list of 31 cards will contain no duplicate cards, and will 
    therefore contain some hearts or spades, represented by H or S.  
    A valid list of 31 cards will therefore never be a valid 
    hexadecimal string.
    """
    cleanString = nonwhitespace(inputString).upper()
    try:
        value = int(cleanString, 16)   # Gives error if not hex.
    except ValueError:
        print(string_to_hex(cleanString))
    else:
        print(integer_to_card_string(value))

def nonwhitespace(argument):
    """Return argument with all whitespace removed.
    
    This includes removing any single spaces within the string.
    """
    return "".join(argument.split())
    
def string_to_hex(cleanString):
    return card_list_to_hex(string_to_card_list(cleanString))
    
def string_to_card_list(cleanString):
    enforce_62_characters(cleanString)
    listOfCards = [cleanString[i:i+2] for i in range(0, 62, 2)]
    check_if_cards(listOfCards)
    check_for_card_repetition(listOfCards)
    return listOfCards

def integer_to_card_string(value):
    enforce_upper_limit(value)
    return valid_integer_to_card_string(value)
    
def enforce_62_characters(argument):
    """Raise an exception if not exactly 31 cards."""
    length = len(argument)
    if length < 62:
        message = (
            "31 cards required, each 2 characters.\n"
            "62 characters required in total.\n"
            "Only " + str(length) + " nonwhitespace characters provided."
            )
        raise TooFewCardsError(message)
    if length > 62:
        message = (
            "31 cards required, each 2 characters.\n"
            "62 characters required in total.\n"
            "" + str(length) + " nonwhitespace characters provided."
            )
        raise TooManyCardsError(message)

def check_if_cards(listOfCards):
    """Raise an exception if not valid cards.
    
    Every card should be a rank character followed by a suit character.
    """
    for i in listOfCards:
        if i[0] not in CARD_RANKS:
            message = (
                "'" + str(i) + "' is not a recognised card rank.\n"
                "A valid rank is a single character as follows:\n"
                "'A' (ace)\n"
                "'2' (two)\n"
                "'3' (three)\n"
                "'4' (four)\n"
                "'5' (five)\n"
                "'6' (six)\n"
                "'7' (seven)\n"
                "'8' (eight)\n"
                "'9' (nine)\n"
                "'T' (ten)\n"
                "'J' (jack)\n"
                "'Q' (queen)\n"
                "'K' (king)"
                )
            raise UnrecognisedCardRankError(message)
        if i[1] not in CARD_SUITS:
            message = (
                "'" + str(i) + "' is not a recognised card suit.\n"
                "A valid suit is a single character as follows:\n"
                "'S' (spades)\n"
                "'H' (hearts)\n"
                "'D' (diamonds)\n"
                "'C' (clubs)"
                )
            raise UnrecognisedCardSuitError(message)
            
def check_for_card_repetition(listOfCards):
    """Check that there are 31 unique pairs of characters.
    
    The list is already known to contain exactly 31 pairs.  Just check 
    that each is unique.
    """
    uniqueCards = set(listOfCards)
    if not len(uniqueCards) == 31:
        message = (
            "No two cards should be the same.\n"
            "Cards should be drawn from a single deck of 52 cards.\n"
            "Cards should be drawn without replacement."
            )
        raise DuplicatedCardsError(message)
        
def enforce_upper_limit(value):
    """Check 0 <= value <= 52!/(52-31)! - 1
    
    As Python's arbitrary precision integers cannot be represented
    in hexadecimal as negative without using a minus sign, which has
    already been precluded, check only the upper limit.
    """
    if value > UPPER_LIMIT:
        message = (
            "The hexadecimal value is too large to be represented by 31 cards.\n"
            "The maximum valid value is 52!/(52-31)! - 1\n"
            "In hexadecimal this maximum is\n"
            "114882682E46B11EADE9F57C1E3E0BBD47FFFFFFF"
            )
        raise HexValueTooLargeError(message)
    
def card_list_to_hex(listOfCards):
    """Return a hexadecimal string defined by the 31 cards.
    
    The 52 cards in the full deck are numbered from 0 to 51.
    The order used here is defined by allCards.
    The 1st card in listOfCards therefore gives a number from 0 to 51.
    Remove this card from the deck so the deck is now numbered from 
    0 to 50.
    The 2nd card in listOfCards now gives a number from 0 to 50.
    Continue in the same way, to convert the 3rd card to a number 
    from 0 to 49, and so on.
    The final (31st) card will be converted to a number from 0 to 21.
    There is now a list of 31 numbers, each in a smaller range than 
    the last.
    Keep the 1st number as it is (multiply by 1).
    Multiply the 2nd number by 52.
    Multiply the 3rd number by 52 * 51.
    Multiply the 4th number by 52 * 51 * 50.
    Continue until all 31 numbers have been updated in this way.
    The required result is the sum of this list of 31 numbers.
    """
    listOfNumbers = []
    deck = ALL_CARDS
    for card in listOfCards:
        number = deck.index(card)
        listOfNumbers.append(number)
        deck.remove(card)
    for n in range(31):
        listOfNumbers[n] *= FACTORIAL_52 // factorial(52-n)
    result = sum(listOfNumbers)
    return hex(result)[2:]
    
def valid_integer_to_card_string(value):
    """Return a string of 31 cards representing the value.
    
    Divide the value by 52 making a note of quotient and remainder.
    The remainder will be a number from 0 to 51.
    Start a list of numbers with this remainder.
    Use the quotient to continue the process.
    Divide the quotient by 51 making a note of quotient and remainder.
    The remainder will be a number from 0 to 50.
    Append this remainder to the list of numbers.
    Use the new quotient to continue the process.
    Continue until the list contains 31 numbers.
    The 1st number will be from 0 to 51, and defines a card from the 
    full deck of 52 cards (in the order defined by allCards).
    The 2nd number will be from 0 to 50, and defines a card from the 
    remaining 51 cards.
    Continue in the same way to convert the remaining numbers to cards.
    """
    deck = ALL_CARDS
    listOfNumbers = []
    listOfCards = []
    for i in range(31):
        divisor = 52 - i
        quotient = value // divisor
        remainder = value % divisor
        listOfNumbers.append(remainder)
        value = quotient
    for cardNumber in listOfNumbers:
        card = deck.pop(cardNumber)
        listOfCards.append(card)
    return " ".join(listOfCards)
    
# Handle the case where this program is called from the command line.
if __name__ == "__main__":
    import sys
    arguments = sys.argv
    if len(arguments) < 2:
        inputString = request_input()
    else:
        inputString = "".join(arguments[1:])
    decide_how_to_convert(inputString)
