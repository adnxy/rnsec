import React from 'react';
import DOMPurify from 'dompurify';
import sanitizeHtml from 'sanitize-html';

export function A({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

export function B() {
  return <div dangerouslySetInnerHTML={{ __html: '<b>static</b>' }} />;
}

export function C({ raw }: { raw: string }) {
  const clean = sanitizeHtml(raw);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
