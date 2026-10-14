/* eslint-disable */
// @ts-nocheck
/*
* This file is a generated Typescript file for GRPC Gateway, DO NOT MODIFY
*/

import * as fm from "../fetch.pb"
export type GetSystemConfigRequest = {
}

export type SystemConfig = {
  endpoints?: Endpoints
}

export type Endpoints = {
  hfBase?: string
}

export class SystemService {
  static GetSystemConfig(req: GetSystemConfigRequest, initReq?: fm.InitReq): Promise<SystemConfig> {
    return fm.fetchReq<GetSystemConfigRequest, SystemConfig>(`/api/v1alpha1/system/config?${fm.renderURLSearchParams(req, [])}`, {...initReq, method: "GET"})
  }
}