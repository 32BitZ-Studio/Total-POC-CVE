FROM ruby:3.2.2
RUN apt-get update -qq && apt-get install -y postgresql-client
WORKDIR /rails-cve-2017-17917
COPY Gemfile /rails-cve-2017-17917/Gemfile
COPY Gemfile.lock /rails-cve-2017-17917/Gemfile.lock
RUN bundle install

COPY entrypoint.sh /usr/bin/
RUN chmod +x /usr/bin/entrypoint.sh
ENTRYPOINT ["entrypoint.sh"]
EXPOSE 3000

CMD ["rails", "server", "-b", "0.0.0.0"]