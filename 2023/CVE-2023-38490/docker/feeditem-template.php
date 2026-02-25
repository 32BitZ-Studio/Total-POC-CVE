<?php snippet('header') ?>

<main>
  <article class="feedarticle">
    <header class="article-header">
      <h1><?= $page->title() ?></h1>
      <time><?= $page->date()->toDate('d F Y') ?></time>
      <?php if ($page->categories()->isNotEmpty()) : ?>
        <p class="tags"><?= $page->categories() ?></p>
      <?php endif ?>
    </header>

    <div class="article-body">
      <?php if ($page->author()->isNotEmpty()): ?>
        <p>by <?= $page->author() ?></p>
      <?php endif ?>
      <?= $page->text()->excerpt(500) ?>
      <a href="<?= $page->link() ?>">Continue reading on Medium</a>
    </div>
  </article>
</main>

<?php snippet('footer') ?>
