import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root',
})
export class WebRequestService {
  private readonly API_URL;

  constructor(private http: HttpClient) {
    this.API_URL = 'https://axios-ssrf.onrender.com/api';
  }

  getFromApi(path: string) {
    return this.http.get(`${this.API_URL}/${path}`);
  }

  postToApi(path: string, body: object) {
    return this.http.post(`${this.API_URL}/${path}`, body);
  }
}
