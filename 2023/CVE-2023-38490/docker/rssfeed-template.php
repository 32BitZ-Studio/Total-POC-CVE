<?php snippet('header') ?>

<main>
  <header>
    <h1><?= $page->title() ?></h1>
  </header>


  <div class="feed">
    <?php foreach ($page->children()->sortBy('date', 'desc') as $item): ?>
    <article>
      <header class="article-header">
        <a href="<?= $item->url() ?>">
          <h2><?= $item->title() ?></h2>
          <time><?= $item->date()->toDate('d F Y') ?></time>
        </a>
      </header>
    </article>
    <?php endforeach ?>
  </div>

</main>
<?php snippet('footer') ?>
