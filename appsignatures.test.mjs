import { describe, it, expect } from 'vitest';
import { listApplications, listCategories, appDomains, categoryDomains } from './appsignatures.mjs';

describe('app/URL signature catalog', () => {
  it('lists distinct, sorted applications', () => {
    const apps = listApplications();
    expect(apps).toContain('YouTube');
    expect(apps).toContain('Netflix');
    expect([...new Set(apps)]).toEqual(apps);   // unique
    expect([...apps].sort()).toEqual(apps);     // sorted
  });

  it('lists content categories', () => {
    expect(listCategories()).toEqual(expect.arrayContaining(['streaming', 'social', 'gaming', 'messaging']));
  });

  it('maps an application to all its identifying domains', () => {
    expect(appDomains('YouTube')).toEqual(expect.arrayContaining(['youtube.com', 'googlevideo.com', 'ytimg.com']));
    expect(appDomains('Nonexistent App')).toEqual([]);
  });

  it('maps a category to its member domains', () => {
    const streaming = categoryDomains('streaming');
    expect(streaming).toContain('netflix.com');
    expect(streaming).toContain('youtube.com');
    expect(categoryDomains('nope')).toEqual([]);
  });
});
