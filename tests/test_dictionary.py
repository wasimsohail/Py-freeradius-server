"""
Unit tests for RADIUS dictionary system

This module tests the dictionary functionality including attribute definitions,
lookups, and the enhanced standard attribute set.
"""

import pytest
from pyfreeradius.dictionary import Dictionary, AttributeDef, create_standard_dictionary


class TestAttributeDef:
    """Test AttributeDef functionality."""

    def test_attribute_def_creation(self):
        """Test creating attribute definitions."""
        attr = AttributeDef("User-Name", 1, "string")

        assert attr.name == "User-Name"
        assert attr.code == 1
        assert attr.type == "string"

    def test_attribute_def_validation(self):
        """Test attribute definition validation."""
        # Valid definition
        attr = AttributeDef("Test-Attr", 100, "integer")
        assert attr.name == "Test-Attr"

        # Invalid name
        with pytest.raises(ValueError, match="Attribute name must be a non-empty string"):
            AttributeDef("", 1, "string")

        # Invalid code (too low)
        with pytest.raises(ValueError, match="Attribute code must be an integer between 1 and 255"):
            AttributeDef("Test", 0, "string")

        # Invalid code (too high)
        with pytest.raises(ValueError, match="Attribute code must be an integer between 1 and 255"):
            AttributeDef("Test", 256, "string")

        # Invalid type
        with pytest.raises(ValueError, match="Attribute type must be a non-empty string"):
            AttributeDef("Test", 1, "")


class TestDictionary:
    """Test Dictionary functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.dictionary = Dictionary()

    def test_empty_dictionary(self):
        """Test empty dictionary."""
        assert len(self.dictionary) == 0
        assert self.dictionary.get_attribute_count() == 0
        assert self.dictionary.get_all_attributes() == []

    def test_add_attribute(self):
        """Test adding attributes."""
        attr = AttributeDef("User-Name", 1, "string")
        self.dictionary.add_attribute(attr)

        assert len(self.dictionary) == 1
        assert self.dictionary.get_attribute_count() == 1
        assert 1 in self.dictionary
        assert "User-Name" in self.dictionary

    def test_lookup_by_name(self):
        """Test lookup by attribute name."""
        attr = AttributeDef("User-Name", 1, "string")
        self.dictionary.add_attribute(attr)

        found = self.dictionary.by_name("User-Name")
        assert found is not None
        assert found.name == "User-Name"
        assert found.code == 1
        assert found.type == "string"

        # Non-existent attribute
        not_found = self.dictionary.by_name("Non-Existent")
        assert not_found is None

    def test_lookup_by_code(self):
        """Test lookup by attribute code."""
        attr = AttributeDef("User-Name", 1, "string")
        self.dictionary.add_attribute(attr)

        found = self.dictionary.by_code(1)
        assert found is not None
        assert found.name == "User-Name"
        assert found.code == 1
        assert found.type == "string"

        # Non-existent attribute
        not_found = self.dictionary.by_code(999)
        assert not_found is None

    def test_add_duplicate_attribute(self):
        """Test adding duplicate attributes."""
        attr1 = AttributeDef("User-Name", 1, "string")
        attr2 = AttributeDef("User-Name", 1, "string")  # Same definition

        self.dictionary.add_attribute(attr1)
        self.dictionary.add_attribute(attr2)  # Should not raise error

        assert len(self.dictionary) == 1  # Only one should be stored

    def test_add_conflicting_attribute_name(self):
        """Test adding conflicting attribute by name."""
        attr1 = AttributeDef("User-Name", 1, "string")
        attr2 = AttributeDef("User-Name", 2, "string")  # Same name, different code

        self.dictionary.add_attribute(attr1)

        with pytest.raises(ValueError, match="Attribute name 'User-Name' already exists"):
            self.dictionary.add_attribute(attr2)

    def test_add_conflicting_attribute_code(self):
        """Test adding conflicting attribute by code."""
        attr1 = AttributeDef("User-Name", 1, "string")
        attr2 = AttributeDef("User-Password", 1, "string")  # Same code, different name

        self.dictionary.add_attribute(attr1)

        with pytest.raises(ValueError, match="Attribute code 1 already exists"):
            self.dictionary.add_attribute(attr2)

    def test_remove_attribute_by_name(self):
        """Test removing attribute by name."""
        attr = AttributeDef("User-Name", 1, "string")
        self.dictionary.add_attribute(attr)

        assert len(self.dictionary) == 1

        removed = self.dictionary.remove_attribute("User-Name")
        assert removed is True
        assert len(self.dictionary) == 0
        assert self.dictionary.by_name("User-Name") is None
        assert self.dictionary.by_code(1) is None

        # Try to remove non-existent
        removed = self.dictionary.remove_attribute("Non-Existent")
        assert removed is False

    def test_remove_attribute_by_code(self):
        """Test removing attribute by code."""
        attr = AttributeDef("User-Name", 1, "string")
        self.dictionary.add_attribute(attr)

        assert len(self.dictionary) == 1

        removed = self.dictionary.remove_attribute(1)
        assert removed is True
        assert len(self.dictionary) == 0
        assert self.dictionary.by_name("User-Name") is None
        assert self.dictionary.by_code(1) is None

        # Try to remove non-existent
        removed = self.dictionary.remove_attribute(999)
        assert removed is False

    def test_get_all_attributes(self):
        """Test getting all attributes."""
        attr1 = AttributeDef("User-Name", 1, "string")
        attr2 = AttributeDef("User-Password", 2, "string")
        attr3 = AttributeDef("NAS-IP-Address", 4, "ipaddr")

        self.dictionary.add_attribute(attr1)
        self.dictionary.add_attribute(attr2)
        self.dictionary.add_attribute(attr3)

        all_attrs = self.dictionary.get_all_attributes()
        assert len(all_attrs) == 3

        # Check all attributes are present
        names = [attr.name for attr in all_attrs]
        assert "User-Name" in names
        assert "User-Password" in names
        assert "NAS-IP-Address" in names

    def test_contains_operator(self):
        """Test __contains__ operator."""
        attr = AttributeDef("User-Name", 1, "string")
        self.dictionary.add_attribute(attr)

        # Test by name
        assert "User-Name" in self.dictionary
        assert "Non-Existent" not in self.dictionary

        # Test by code
        assert 1 in self.dictionary
        assert 999 not in self.dictionary

        # Test invalid type
        assert 1.5 not in self.dictionary


class TestStandardDictionary:
    """Test standard dictionary creation."""

    def test_create_standard_dictionary(self):
        """Test creating standard dictionary."""
        dictionary = create_standard_dictionary()

        # Should have many attributes
        assert len(dictionary) > 50  # We added many standard attributes

        # Check some core RFC 2865 attributes
        user_name = dictionary.by_name("User-Name")
        assert user_name is not None
        assert user_name.code == 1
        assert user_name.type == "string"

        user_password = dictionary.by_name("User-Password")
        assert user_password is not None
        assert user_password.code == 2
        assert user_password.type == "string"

        nas_ip = dictionary.by_name("NAS-IP-Address")
        assert nas_ip is not None
        assert nas_ip.code == 4
        assert nas_ip.type == "ipaddr"

        # Check some accounting attributes
        acct_status = dictionary.by_name("Acct-Status-Type")
        assert acct_status is not None
        assert acct_status.code == 40
        assert acct_status.type == "integer"

        # Check some extended attributes
        eap_message = dictionary.by_name("EAP-Message")
        assert eap_message is not None
        assert eap_message.code == 79
        assert eap_message.type == "octets"

        # Check IPv6 attributes
        nas_ipv6 = dictionary.by_name("NAS-IPv6-Address")
        assert nas_ipv6 is not None
        assert nas_ipv6.code == 95
        assert nas_ipv6.type == "octets"

    def test_standard_dictionary_attribute_types(self):
        """Test that standard dictionary has correct attribute types."""
        dictionary = create_standard_dictionary()

                # String attributes
        attr1 = dictionary.by_code(1)
        assert attr1 is not None and attr1.type == "string"    # User-Name
        attr18 = dictionary.by_code(18)
        assert attr18 is not None and attr18.type == "string"   # Reply-Message
        attr44 = dictionary.by_code(44)
        assert attr44 is not None and attr44.type == "string"   # Acct-Session-Id

        # Integer attributes
        attr5 = dictionary.by_code(5)
        assert attr5 is not None and attr5.type == "integer"   # NAS-Port
        attr27 = dictionary.by_code(27)
        assert attr27 is not None and attr27.type == "integer"  # Session-Timeout
        attr40 = dictionary.by_code(40)
        assert attr40 is not None and attr40.type == "integer"  # Acct-Status-Type

        # IP address attributes
        attr4 = dictionary.by_code(4)
        assert attr4 is not None and attr4.type == "ipaddr"    # NAS-IP-Address
        attr8 = dictionary.by_code(8)
        assert attr8 is not None and attr8.type == "ipaddr"    # Framed-IP-Address

        # Octets attributes
        attr3 = dictionary.by_code(3)
        assert attr3 is not None and attr3.type == "octets"    # CHAP-Password
        attr24 = dictionary.by_code(24)
        assert attr24 is not None and attr24.type == "octets"   # State
        attr79 = dictionary.by_code(79)
        assert attr79 is not None and attr79.type == "octets"   # EAP-Message

    def test_standard_dictionary_no_duplicates(self):
        """Test that standard dictionary has no duplicate codes or names."""
        dictionary = create_standard_dictionary()

        all_attrs = dictionary.get_all_attributes()

        # Check for duplicate codes
        codes = [attr.code for attr in all_attrs]
        assert len(codes) == len(set(codes)), "Found duplicate attribute codes"

        # Check for duplicate names
        names = [attr.name for attr in all_attrs]
        assert len(names) == len(set(names)), "Found duplicate attribute names"

    def test_standard_dictionary_coverage(self):
        """Test coverage of standard attributes."""
        dictionary = create_standard_dictionary()

        # Should have all RFC 2865 core attributes (1-39, with some gaps)
        core_attrs = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                     18, 19, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
                     33, 34, 35, 36, 37, 38, 39]

        for code in core_attrs:
            attr = dictionary.by_code(code)
            assert attr is not None, f"Missing core attribute {code}"

        # Should have accounting attributes (40-49)
        acct_attrs = [40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51]

        for code in acct_attrs:
            attr = dictionary.by_code(code)
            assert attr is not None, f"Missing accounting attribute {code}"

        # Should have some extended attributes
        extended_attrs = [60, 61, 79, 80, 87, 95]

        for code in extended_attrs:
            attr = dictionary.by_code(code)
            assert attr is not None, f"Missing extended attribute {code}"


class TestDictionaryStringRepresentation:
    """Test dictionary string representations."""

    def test_dict_str(self):
        """Test dictionary __str__ method."""
        dictionary = Dictionary()

        # Empty dictionary
        assert str(dictionary) == "Dictionary(0 attributes)"

        # Add some attributes
        dictionary.add_attribute(AttributeDef("User-Name", 1, "string"))
        dictionary.add_attribute(AttributeDef("User-Password", 2, "string"))

        assert str(dictionary) == "Dictionary(2 attributes)"

    def test_dict_repr(self):
        """Test dictionary __repr__ method."""
        dictionary = Dictionary()

        # Empty dictionary
        assert repr(dictionary) == "Dictionary(attributes=0)"

        # Add some attributes
        dictionary.add_attribute(AttributeDef("User-Name", 1, "string"))

        assert repr(dictionary) == "Dictionary(attributes=1)"
