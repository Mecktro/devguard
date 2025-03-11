// Copyright (C) 2025 timbastin
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package events_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestReadAssetEventsByVulnID(t *testing.T) {
	t.Run("should return 400 if vulnId is missing", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/vuln-events", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockRepository := mocks.NewCoreVulnEventRepository(t)
		// Execution
		err := events.NewVulnEventController(mockRepository).ReadAssetEventsByVulnID(c)

		// Assertion
		assert.NotNil(t, err)
		assert.Equal(t, 400, err.(*echo.HTTPError).Code)
	})

	t.Run("should return 500 if repository returns an error", func(t *testing.T) {
		mockRepository := mocks.NewCoreVulnEventRepository(t)
		mockRepository.On("ReadAssetEventsByVulnID", "vulnId").Return(nil, assert.AnError)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/vuln-events?vulnId=vulnId", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("dependencyVulnId")
		c.SetParamValues("vulnId")

		// Execution
		err := events.NewVulnEventController(mockRepository).ReadAssetEventsByVulnID(c)

		// Assertion
		assert.NotNil(t, err)
		assert.Equal(t, 500, err.(*echo.HTTPError).Code)
	})
}
