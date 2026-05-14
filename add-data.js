require('dotenv').config();
const db = require('./db');

async function addRussianData() {
  try {
    await db.query(`UPDATE departments SET name='Отдел 1' WHERE name='Otdel 1'`);
    await db.query(`UPDATE departments SET name='Отдел 2' WHERE name='Otdel 2'`);
    await db.query(`UPDATE departments SET name='Отдел 3' WHERE name='Otdel 3'`);

    await db.query(`UPDATE agents SET full_name='Алишер' WHERE login='Alisher'`);
    await db.query(`UPDATE agents SET full_name='Айдос' WHERE login='Aidos'`);
    await db.query(`UPDATE agents SET full_name='Тест' WHERE login='Test'`);
    await db.query(`UPDATE agents SET full_name='Алибек Джаксыбеков' WHERE login='alibek'`);
    await db.query(`UPDATE agents SET full_name='Айгерим Касымова' WHERE login='aigerim'`);
    await db.query(`UPDATE agents SET full_name='Дмитрий Коваленко' WHERE login='dmitriy'`);

    await db.query(`UPDATE outlets SET name='Магазин Береке', address='ул. Ленина 45' WHERE name='Magazin Bereke' OR name='Magazin Bereke v2'`);

    console.log('Готово!');
    process.exit(0);
  } catch (err) {
    console.error('Ошибка:', err.message);
    process.exit(1);
  }
}

addRussianData();