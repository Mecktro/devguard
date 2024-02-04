// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
package utils

import "testing"

func TestSemverOrNil(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		semver := SemverOrNil("")
		if semver != nil {
			t.Errorf("Expected nil, got %s", *semver)
		}
	})

	t.Run("valid semver", func(t *testing.T) {
		semver := SemverOrNil("1.14.14")
		if *semver != "1.14.14" {
			t.Errorf("Expected 1.14.14, got %s", *semver)
		}
	})

	t.Run("invalid semver", func(t *testing.T) {
		// do a table driven test for the invalid semver
		invalidSemvers := []struct {
			input    string
			expected string
		}{
			{"1.14", "1.14.0"},
			{"1.0", "1.0.0"},
			{"19.03.9", "19.3.9"},
			{"3.0-beta1", "3.0.0-beta1"},
		}
		for _, tt := range invalidSemvers {
			semver := SemverOrNil(tt.input)

			if *semver != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, *semver)
			}
		}
	})

}
