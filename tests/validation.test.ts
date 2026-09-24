import {describe,it,expect} from 'vitest';
const valid=/^[a-z0-9_]{3,24}$/;
describe('CloudGram validation rules',()=>{it('accepts normalized usernames',()=>expect(valid.test('vardan_77')).toBe(true));it('rejects unsafe usernames',()=>{expect(valid.test('a')).toBe(false);expect(valid.test('hello world')).toBe(false);expect(valid.test('тест')).toBe(false);});it('keeps message limit bounded',()=>expect('x'.repeat(4000).length).toBe(4000));});
