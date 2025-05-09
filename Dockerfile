# Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

FROM golang:1.24.0 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN CGO_ENABLED=0 make devguard
RUN CGO_ENABLED=0 make devguard-cli

FROM alpine:3.20.2@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5

WORKDIR /

COPY config/rbac_model.conf /config/rbac_model.conf
COPY --from=build /go/src/app/devguard /usr/local/bin/devguard
COPY --from=build /go/src/app/devguard-cli /usr/local/bin/devguard-cli
COPY templates /templates
COPY intoto-public-key.pem /intoto-public-key.pem
COPY cosign.pub /cosign.pub

CMD ["devguard"]